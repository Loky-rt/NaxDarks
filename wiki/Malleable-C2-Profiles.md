# Malleable C2 Profiles

NaxDarks implements a **Malleable C2 Profile v2** system for HTTPS transport. Profiles customize every aspect of the HTTP(S) communication between the agent and the C2 server: URIs, headers, cookies, query parameters, body encoding, XOR masking, and server response formatting.

---

## Overview

The HTTPS transport uses a two-phase communication model:

1. **Pre-profile (bootstrap)**
   The agent connects with hardcoded defaults (`/news/feed`, `/api/submit`, `X-Beacon-Id` header). It sends a REGISTER frame encrypted with AES-128-CBC. The server responds with a **PROFILE frame** (raw AES-CBC, no encoding).

2. **Post-profile (malleable)**
   Once the agent applies the profile, all subsequent communication uses the URI rotation, header/cookie/parameter placement, body encoding, XOR masking, and response decoding defined in the profile.

> **Important:** The REGISTER request is **always** sent pre-profile. The server always accepts `X-Beacon-Id` as a bootstrap header regardless of what `beacon_id_header` the profile defines. This ensures new agents can register even after runtime profile changes.

---

## Profile JSON Structure

```json
{
  "callbacks": [
    {
      "hosts": ["192.168.100.129:2525"],
      "user_agent": "Amazon CloudFront",
      "beacon_id_header": "X-Amz-Cf-Id",
      "rotation": "random",
      "server_error": { ... },
      "get": { ... },
      "post": { ... }
    }
  ]
}
```

---

## Callback Object

| Field | Type | Description |
|-------|------|-------------|
| `hosts` | `array` | C2 callback hosts in `"host:port"` format. Used for host rotation. |
| `user_agent` | `string` | User-Agent header on all requests. |
| `beacon_id_header` | `string` | Header name for the beacon session ID after profile load. Pre-profile always uses `X-Beacon-Id`. |
| `rotation` | `string` | URI rotation mode: `"sequential"` or `"random"`. |
| `server_error` | `object` | HTTP response sent when the server rejects a request. |
| `get` | `object` | Configuration for GET (heartbeat) requests. |
| `post` | `object` | Configuration for POST (result) requests. |

### `server_error` Object

| Field | Type | Description |
|-------|------|-------------|
| `status` | `int` | HTTP status code (e.g. `503`, `404`, `401`). |
| `body` | `string` | Response body text. |
| `headers` | `object` | Response headers as key-value pairs. |

---

## GET / POST Transaction Object

Both `get` and `post` share the same structure:

```json
{
  "uri": ["/path1", "/path2"],
  "client": {
    "headers": { "Accept": "application/json" },
    "metadata": { OutputConfig },
    "output": { OutputConfig },
    "parameters": { "key": "value" }
  },
  "server": {
    "headers": { "Content-Type": "application/json" },
    "output": { OutputConfig }
  }
}
```

| Field | GET | POST | Description |
|-------|-----|------|-------------|
| `uri` | ✓ | ✓ | URI paths to rotate through. |
| `client.headers` | ✓ | ✓ | Custom request headers. |
| `client.metadata` | ✓ | ✓ | **OutputConfig** — how the **session ID** is encoded and placed. |
| `client.output` | ✗ | ✓ | **OutputConfig** — how the **encrypted result data** is encoded and placed. |
| `client.parameters` | ✓ | ✗ | Static query parameters appended to the URI. |
| `server.headers` | ✓ | ✓ | Headers the server includes in its response. |
| `server.output` | ✓ | ✓ | **OutputConfig** — how the server encodes its response body. |

### Three Separate Encode Configs

This is critical to understand — the agent uses **three independent OutputConfig** objects:

| Config | Used for | Example |
|--------|----------|---------|
| `get.client.metadata` | Encoding the encrypted **heartbeat** into the GET request | Session ID in cookie `__cfduid` with base64+mask |
| `post.client.metadata` | Encoding the **session ID** into the POST request | Session ID in header `X-Request-Id` with base64url |
| `post.client.output` | Encoding the **encrypted result** into the POST body | Result in body with hex+mask+JSON wrapper |

Each config has its own `format`, `mask`, `placement`, `prepend`, and `append`. They are **completely independent** — changing one does not affect the others.

---

## OutputConfig Object

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `format` | `string` | `"raw"` | `"raw"`, `"base64"`, `"base64url"`, or `"hex"` |
| `mask` | `bool` | `false` | XOR-mask the data with a 4-byte random key |
| `placement` | `string` | `"body"` | `"body"`, `"header"`, `"cookie"`, or `"parameter"` |
| `name` | `string` | `""` | Header/cookie/parameter name (ignored for `"body"`) |
| `prepend` | `string` | `""` | Static text prepended to the encoded data |
| `append` | `string` | `""` | Static text appended to the encoded data |
| `empty_response` | `string` | `""` | Verbatim response when no data is available (server-side only) |

### Format Details

| Format | Encoding | Padding | Characters |
|--------|----------|---------|------------|
| `raw` | No encoding | N/A | Binary data |
| `base64` | Standard Base64 | `=` padding | `A-Za-z0-9+/=` |
| `base64url` | URL-safe Base64 | **No padding** | `A-Za-z0-9-_` |
| `hex` | Lowercase hexadecimal | N/A | `0-9a-f` |

---

## Encoding Pipeline

### Client → Server (Agent encodes)

```
Raw data
  ↓
[1] XOR Mask (if mask: true)
    → Generate 4 random bytes (key)
    → XOR each byte with key[i % 4]
    → Prepend key to masked data
  ↓
[2] Format Encode (base64 / base64url / hex / raw)
  ↓
[3] Prepend + Encoded + Append
  ↓
[4] Place in body / header / cookie / parameter
```

### Server → Client (Agent decodes)

```
HTTP response
  ↓
[1] Extract from body (strip HTTP headers)
  ↓
[2] Strip Prepend and Append
  ↓
[3] Format Decode
  ↓
[4] XOR Unmask (if mask: true)
    → Read first 4 bytes as key
    → XOR remaining bytes with key[i % 4]
  ↓
Raw decrypted data
```

---

## Runtime Profile Update

The `profile_update` command allows changing the agent's profile without reconnecting:

```
profile_update /path/to/new-profile.json
```

### Deferred Application

The profile is **not** applied immediately. The agent stores it as pending and applies it **after** sending the confirmation result with the **old** profile. This prevents a timing race where the result would be encoded with the new profile before the server knows about it.

### Flow

```
Operator                    Agent Plugin                    Listener                    Agent
   │                             │                             │                          │
   │── profile_update ──────────>│                             │                          │
   │                             │                             │                          │
   │                             │── CMD_PROFILE_UPDATE ──────────────────────────────────>│
   │                             │                             │                          │
   │                             │                             │    ① nax_profile_set_pending()
   │                             │                             │       (stores but does NOT apply)
   │                             │                             │    ② profile_burst_until = now + 3s
   │                             │                             │       (skip sleep for fast transition)
   │                             │                             │
   │                             │                             │<──③ result: "Profile queued"
   │                             │                             │       (encoded with OLD profile ✓)
   │                             │                             │
   │                             │④ ProcessData receives result│                          │
   │                             │   detects CMD_PROFILE_UPDATE│                          │
   │                             │── saveProfileToStore() ────>│                          │
   │                             │   (TsExtenderData)          │── pollProfileStore()     │
   │                             │                             │   loads new profile       │
   │                             │                             │                          │
   │                             │                             │    ⑤ nax_profile_apply_pending()
   │                             │                             │       (applies new profile AFTER sleep)
   │                             │                             │
   │                             │                             │<──⑥ next GET uses new profile
   │                             │                             │       server already has it from store ✓
   │                             │                             │
   │                             │                             │    ⑦ burst expires (3s) → normal sleep
```

### Step-by-step breakdown

1. **Operator** runs `profile_update new-profile.json`. The agent plugin parses the JSON, encodes to wire v2 format, stores the `ProfileConfig` in `pendingProfiles` map, and sends `CMD_PROFILE_UPDATE` to the agent.

2. **Agent** receives the task. `cmd_profile_update()` calls `nax_profile_set_pending()` which deep-copies the profile data but does **not** call `nax_apply_profile()`. It also sets `profile_burst_until = now + 3s` to temporarily skip sleep.

3. **Agent** sends the result `"Profile queued — applying on next heartbeat"` encoded with the **old** profile. The server decodes it successfully because it still uses the old profile.

4. **Server** receives the result in `ProcessData()`. It detects `CMD_PROFILE_UPDATE` by checking the pending command ID, loads the `ProfileConfig` from `pendingProfiles`, and calls `saveProfileToStore()` to persist it in `TsExtenderData("nax_profiles")`. The listener picks it up on the next `pollProfileStore()` cycle (every 5 seconds).

5. **Agent** reaches the sleep section of the heartbeat loop. Before sleeping, it calls `nax_profile_apply_pending()` which applies the new profile. The next heartbeat will use the new URIs, headers, encoding, etc.

6. **Agent** sends the next GET heartbeat using the **new** profile. The listener already has the new profile loaded from the store, so it decodes successfully.

7. After 3 seconds, the burst window expires and the agent returns to its normal sleep interval.

### Handling long sleep intervals

Without the burst mechanism, an agent with `sleep=20s` would wait 20 seconds before its next heartbeat after applying the new profile. The `pollProfileStore()` on the server (every 5s) would load the new profile, but the server would also still have the old profile in `agentPrevProfiles`. During the transition, the server tries decoding with the new profile first, then falls back to the previous one.

The burst mechanism (`profile_burst_until`) ensures fast transition regardless of sleep interval:
- The agent skips its configured sleep for 3 seconds after receiving `profile_update`
- This guarantees at least one full heartbeat cycle with the new profile within 3 seconds
- After the burst window, the agent resumes its normal sleep/jitter schedule

### Key behaviors

- The listener **always** keeps `X-Beacon-Id` in its accepted headers list (via `rebuildBeaconIDHeaders()`), so new pre-profile agents can register regardless of how many profile updates have been applied to other agents.
- When a profile is updated, the **previous** profile is preserved in `agentPrevProfiles`. During the transition window, the server tries: agent-specific override → previous override → listener default.
- Profile overrides are persisted in `TsExtenderData("nax_profiles")`. The listener polls every 5 seconds for changes.
- When an agent is removed from Adaptix, its profile override is automatically cleaned up on the next `reloadAllProfiles()` cycle.
- The confirmation result is **always** sent with the old profile, and the new profile is saved to the store **only** after the server receives this confirmation. This eliminates the timing race that caused failures with high sleep values.

---

## Pre-Profile vs Post-Profile

| Aspect | Pre-Profile (bootstrap) | Post-Profile (malleable) |
|--------|------------------------|--------------------------|
| **GET URI** | `/news/feed` | Rotated from `get.uri` array |
| **POST URI** | `/api/submit` | Rotated from `post.uri` array |
| **Beacon ID** | `X-Beacon-Id` header | Profile's `beacon_id_header` |
| **GET body** | Raw AES-CBC heartbeat | Encoded per `get.client.metadata` |
| **POST body** | Raw AES-CBC result | Encoded per `post.client.output` |
| **POST metadata** | Not sent | Encoded per `post.client.metadata` |
| **Server response** | Raw AES-CBC (PROFILE frame) | Encoded per `server.output` |
| **Query params** | None | From `client.parameters` |

---

## Host Rotation

The `hosts` array defines multiple C2 endpoints. The `rotation` field controls selection:

- `"sequential"` — Iterate in order, wrapping around.
- `"random"` — Pick a random host each time.

If a connection fails, the agent rotates to the next host immediately.

---

## Built-in Profiles

| File | Description | Key Features |
|------|-------------|--------------|
| `aws-cloudfront.json` | Mimics AWS CloudFront CDN | Cookie metadata, hex+mask body, JSON wrappers |
| `jquery-stealth.json` | Mimics jQuery CDN fetch | Cookie metadata with base64+mask, JS comment wrappers |
| `microsoft-graph.json` | Mimics Microsoft Graph API | Header metadata with hex+mask, JSON API wrappers |

---

## Complete Example: AWS CloudFront Profile

```json
{
  "callbacks": [
    {
      "hosts": ["192.168.100.129:2525"],
      "user_agent": "Amazon CloudFront",
      "beacon_id_header": "X-Amz-Cf-Id",
      "rotation": "random",

      "server_error": {
        "status": 503,
        "body": "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>ServiceUnavailable</Code></Error>",
        "headers": {
          "Content-Type": "text/xml",
          "Server": "AmazonS3"
        }
      },

      "get": {
        "uri": ["/d/cf-dist/assets/main.woff2", "/d/cf-dist/css/styles.min.css"],
        "client": {
          "headers": { "Accept": "*/*", "Origin": "https://cdn.example.com" },
          "metadata": {
            "format": "hex",
            "mask": false,
            "placement": "cookie",
            "name": "CloudFront-Key-Pair-Id",
            "prepend": "APKA",
            "append": ""
          },
          "parameters": { "Expires": "1733011200" }
        },
        "server": {
          "headers": { "Content-Type": "font/woff2", "X-Cache": "Hit from cloudfront" },
          "output": {
            "format": "base64url",
            "mask": false,
            "placement": "body",
            "prepend": "",
            "append": "",
            "empty_response": ""
          }
        }
      },

      "post": {
        "uri": ["/prod/api/events", "/prod/api/metrics"],
        "client": {
          "headers": { "Content-Type": "application/x-amz-json-1.1" },
          "metadata": {
            "format": "raw",
            "mask": false,
            "placement": "parameter",
            "name": "X-Amz-Security-Token",
            "prepend": "",
            "append": ""
          },
          "output": {
            "format": "hex",
            "mask": true,
            "placement": "body",
            "prepend": "{\"logEvents\":[{\"message\":\"",
            "append": "\"}]}"
          }
        },
        "server": {
          "headers": { "Content-Type": "application/x-amz-json-1.1" },
          "output": {
            "format": "hex",
            "mask": false,
            "placement": "body",
            "prepend": "{\"_data\":\"",
            "append": "\"}",
            "empty_response": "{\"nextSequenceToken\":\"49641086694350286920040691822737707098\"}"
          }
        }
      }
    }
  ]
}
```

### How this profile works

| Aspect | GET (Heartbeat) | POST (Results) |
|--------|-----------------|----------------|
| **Session ID** | Hex in cookie `CloudFront-Key-Pair-Id` with `APKA` prefix | Raw in query parameter `X-Amz-Security-Token` |
| **Data payload** | N/A (heartbeat only) | Hex + XOR-masked in body, wrapped in JSON |
| **Server response** | Base64url in body (no mask) | Hex in body, wrapped in JSON `_data` field |
| **Empty response** | Empty body | `{"nextSequenceToken":"..."}` verbatim |
| **Appearance** | Browser fetching CDN font/CSS files | Lambda function posting CloudWatch logs |

---

## Server-Side Architecture

### Request Processing

1. **`rootHandler()`** — Extracts beacon ID from any known header (always includes `X-Beacon-Id` as fallback).
2. **`beaconHandler()`** — Routes to create (new agent) or process (existing agent).
3. **`tryDecodeWithProfile()`** — Tries to decode with: agent override → previous override → default profile.
4. **`writeServerResponse()`** — Applies encoding pipeline (mask → format → prepend/append) to response data.

### Per-Agent Profile Store

The server maintains per-agent profile overrides via `TsExtenderData("nax_profiles")`:

- **`pollProfileStore()`** — Checks for new/updated profiles every 5 seconds.
- **`loadProfileFromStore()`** — Parses stored profile JSON into `ProfileConfig`, preserves previous profile.
- **`rebuildBeaconIDHeaders()`** — Rebuilds the accepted beacon ID headers list (always includes `X-Beacon-Id`).
- **`reloadAllProfiles()`** — Syncs map with store, removes stale entries for deleted agents.

---

## Wire Format (v2)

The profile is serialized in binary v2 wire format for transmission from server to agent:

```
[version: 1 byte (0x02)]
[rotation: 1 byte]
[user_agent: lpstr]
[beacon_id_header: lpstr]
[hosts: string_list]
[error: status(2) + body(lpstr) + headers(header_map)]
[GET: uris(string_list) + client_meta(output_cfg) + client_headers(header_map) + client_params(string_list) + server_output(output_cfg) + server_headers(header_map)]
[POST: uris(string_list) + client_meta(output_cfg) + client_output(output_cfg) + client_headers(header_map) + server_output(output_cfg) + server_headers(header_map)]
```

Where:
- `lpstr` = `[length: 2 bytes LE][string bytes]`
- `string_list` = `[count: 2 bytes LE][lpstr...]`
- `header_map` = string_list of `"Key: Value"` strings
- `output_cfg` = `[format: 1][mask: 1][placement: 1][name: lpstr][prepend: lpstr][append: lpstr][empty_resp: lpstr]`

> **Note:** POST `client_params` are NOT included in the wire format. Only GET `client_params` are serialized. POST parameters, if needed, must be added server-side.

---

## References

- **Agent encoding:** `nax_linux/src/Transport/https_profile.c` — `nax_encode_get_meta()`, `nax_encode_post_meta()`, `nax_encode_post_output()`
- **Agent transport:** `nax_linux/src/Transport/https.c` — `https_get()`, `https_post()`
- **Server transforms:** `src_server/listener_naxdarks_linux_https/pl_http_transform.go`
- **Server handler:** `src_server/listener_naxdarks_linux_https/pl_http.go`
- **Profile store:** `src_server/listener_naxdarks_linux_https/pl_http_profile_store.go`
- **Wire encoder:** `agent_naxdarks_linux/pl_wire.go` — `EncodeProfileBodyV2()`
- **Profile store (agent plugin):** `agent_naxdarks_linux/pl_profile.go`
- **Example profiles:** `profiles/aws-cloudfront.json`, `profiles/jquery-stealth.json`, `profiles/microsoft-graph.json`
