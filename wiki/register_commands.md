# Registering a New Command in the NAX Linux Agent

This guide explains, step by step, how to add a new command to the agent, using the **cat** command as a reference example. The process involves four files that must be modified in order.

---

## General Architecture

When the operator enters a command in the Adaptix UI, the following flow takes place:

```
operator (UI)
    │
    ▼
ax_config.axs          ← Command registration, UI, arguments
    │
    ▼
pl_commands.go         ← Constructs the TaskData and serializes it to the wire format.
    │
    ▼
PackTasks()            ← Encapsulates into frames and sends to the agent via TCP/HTTPS.
    │
    ▼
nax_dispatch() [C]     ← Receives the cmd_id and dispatches it to the correct handler.
    │
    ▼
cmd_xxx() [C]          ← Actual Command Implementation in the Agent

    │
    ▼
pl_results.go          ← Receives the result and determines how to display it
pl_format.go           ← Formats the output text
```

---

## Files to Modify

| File | Responsibility |
|---------|----------------|
| `nax_linux/include/nax_linux.h` | Define the `NAX_CMD_*` constant |
| `nax_linux/src/Commands/commands.c` | Implement the C function and register it in the dispatch |
| `agent_naxdarks_linux/pl_commands.go` | Define the Go constant and build the `TaskData` |
| `agent_naxdarks_linux/ax_config.axs` | Register the command in the Adaptix UI |
| `agent_naxdarks_linux/pl_format.go` | (Optional) Control how the result is displayed |

---

## Step 1 — Define the Command Constant in `nax_linux.h`	

Each command has a 1-byte numeric ID that identifies the operation in the wire protocol. This ID must be unique and consistent between the server (Go) and the agent (C).

**File:** `nax_linux/include/nax_linux.h`

```c
/* ===== command IDs ===== */
#define NAX_CMD_WHOAMI       0x10u
#define NAX_CMD_EXIT_THREAD  0x12u
#define NAX_CMD_EXIT_PROCESS 0x13u
#define NAX_CMD_CD           0x14u
#define NAX_CMD_PWD          0x15u
#define NAX_CMD_MKDIR        0x16u
#define NAX_CMD_RMDIR        0x17u
#define NAX_CMD_CAT          0x18u   // ← cat use 0x18
#define NAX_CMD_LS           0x19u
// ... remaining commands
```

**Rule**: Choose an unused hexadecimal value that is not already in use.

---
## Step 2 — Implement the Handler in C (`commands.c`)

### 2a. Add the prototype (if it is a static function)

At the beginning of the file, along with the other prototypes:

```c
static uint8_t cmd_cat(NaxAgent *a, NaxTask *t, uint8_t **out, uint32_t *out_len);
```

### 2b. Implement the function

All handlers have the same signature:

```c
static uint8_t cmd_NOMBRE(NaxAgent *a, NaxTask *t,
                           uint8_t **out, uint32_t *out_len)
```

**Parameters:**
- `a` — agent instance (config, state, etc.)
- `t` — Received task: contains `t->args` (argument bytes) and `t->args_len`
- `out` — pointer where the result is written (heap-allocated)
- `out_len` — result size

**Return values:**
- `NAX_STATUS_OK` — success
- `NAX_STATUS_ERR` — error (the server displays it in red)

**Implementation** of `cmd_cat`:**

```c
/* ===== cmd_cat ===== */
static uint8_t cmd_cat(NaxAgent *a, NaxTask *t,
                        uint8_t **out, uint32_t *out_len)
{
    (void)a;
    char *path = args_to_str(t);
    if (!path) {
        *out     = (uint8_t *)strdup("cat: path required");
        *out_len = 18;
        return NAX_STATUS_ERR;
    }

    FILE *f = fopen(path, "rb");
    if (!f) {
        char buf[512];
        snprintf(buf, sizeof(buf), "cat: %s: %s", path, strerror(errno));
        free(path);
        *out     = (uint8_t *)strdup(buf);
        *out_len = strlen(buf);
        return NAX_STATUS_ERR;
    }
    free(path);

    OutBuf ob = {0};
    uint8_t tmp[4096];
    size_t r;
    while ((r = fread(tmp, 1, sizeof(tmp), f)) > 0)
        ob_append(&ob, tmp, (uint32_t)r);
    fclose(f);

    *out     = ob.buf;
    *out_len = ob.len;
    return NAX_STATUS_OK;
}
```

**Helpers available:**

| Helper | Description |
|--------|-------------|
| `args_to_str(t)` | Reads the first string argument from `t->args`. Returns a `char*` that the caller must free with `free()` |
| `ob_append(&ob, data, len)` | Appends bytes to the `OutBuf`. Automatically calls `realloc` |
| `ob_appendf(&ob, fmt, ...)` | Same as `ob_append`, but with `printf` style formatting. |
| `nax_read_lenstr(buf, buflen, &off, &slen)` | Reads a length-prefixed string (4-byte LE) from an arbitrary buffer. Useful for commands with multiple arguments |

### 2c. Register it in `nax_dispatch()`

At the end of the file, in the `nax_dispatch()` function, add the new `case`:

```c
uint8_t nax_dispatch(NaxAgent *a, NaxTask *t,
                     uint8_t **out, uint32_t *out_len)
{
    switch (t->cmd_id) {
    case NAX_CMD_WHOAMI:       return cmd_whoami(a, t, out, out_len);
    case NAX_CMD_PWD:          return cmd_pwd(a, t, out, out_len);
    case NAX_CMD_CD:           return cmd_cd(a, t, out, out_len);
    case NAX_CMD_LS:           return cmd_ls(a, t, out, out_len);
    case NAX_CMD_MKDIR:        return cmd_mkdir(a, t, out, out_len);
    case NAX_CMD_RMDIR:        return cmd_rmdir(a, t, out, out_len);
    case NAX_CMD_RM:           return cmd_rm(a, t, out, out_len);
    case NAX_CMD_CAT:          return cmd_cat(a, t, out, out_len);  // ← aquí
    // ... resto
    default:
        return NAX_STATUS_ERR;
    }
}
```

---

## Step 3 — Define the Constant and Handler in Go (`pl_commands.go`)

### 3a. Add the Go constant

The `const` block at the beginning of the file must use the same numeric value as the `#define` in C:

```go
// Command IDs — must match nax_linux.h NAX_CMD_* in the C agent.
const (
    CMD_WHOAMI       byte = 0x10
    CMD_EXIT_THREAD  byte = 0x12
    CMD_EXIT_PROCESS byte = 0x13
    CMD_CD           byte = 0x14
    CMD_PWD          byte = 0x15
    CMD_MKDIR        byte = 0x16
    CMD_RMDIR        byte = 0x17
    CMD_CAT          byte = 0x18   // ← It must match NAX_CMD_CAT
    CMD_LS           byte = 0x19
    // ...
)
```

### 3b. Add the `case` in `CreateCommand()`

`CreateCommand` receives the `command` (the command name) and `args` (a map containing the operator's arguments), and returns an `adaptix.TaskData` with the payload serialized for the agent.


```go
func CreateCommand(agentData adaptix.AgentData, args map[string]any) (adaptix.TaskData, adaptix.ConsoleMessageData, error) {
    command, _    := args["command"].(string)
    subcommand, _ := args["subcommand"].(string)
    _ = subcommand

    switch command {

    // ... other commands ...

    case "cat":
        path, _ := args["path"].(string)
        if path == "" {
            return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
                fmt.Errorf("cat: path required")
        }
        return pathCmd(CMD_CAT, path), adaptix.ConsoleMessageData{}, nil

    // ...
    }
}
```

### 3c. Serialization Helpers

The file provides two helpers for the most common use cases:

```go
// simpleCmd — Command without arguments
// Wire format: [cmd_id(1)][args_len=0(4)]
func simpleCmd(cmdId byte) adaptix.TaskData {
    return adaptix.TaskData{
        Type: adaptix.TASK_TYPE_TASK,
        Sync: true,
        Data: []byte{cmdId, 0x00, 0x00, 0x00, 0x00},
    }
}

// pathCmd — command with a single string argument
// Wire format: [cmd_id(1)][args_len(4)][len(4)][string bytes]
func pathCmd(cmdId byte, path string) adaptix.TaskData {
    args := packString(path)   // [u32-le len][bytes]
    data := make([]byte, 1+4+len(args))
    data[0] = cmdId
    binary.LittleEndian.PutUint32(data[1:], uint32(len(args)))
    copy(data[5:], args)
    return adaptix.TaskData{Type: adaptix.TASK_TYPE_TASK, Sync: true, Data: data}
}

// `packString` — serializes a string as `[u32-le length][bytes]`
func packString(s string) []byte {
    b   := []byte(s)
    out := make([]byte, 4+len(b))
    binary.LittleEndian.PutUint32(out, uint32(len(b)))
    copy(out[4:], b)
    return out
}
```

**For commands with multiple arguments**, the payload is built manually:

```go
case "multi_example":
    name, _ := args["name"].(string)
    value, _  := args["value"].(string)

    nameBytes := packString(name)
    valueBytes  := packString(value)
    argsBytes   := append(nameBytes, valueBytes...)

    data := make([]byte, 1+4+len(argsBytes))
    data[0] = CMD_EXAMPLE
    binary.LittleEndian.PutUint32(data[1:5], uint32(len(argsBytes)))
    copy(data[5:], argsBytes)

    return adaptix.TaskData{Type: adaptix.TASK_TYPE_TASK, Sync: true, Data: data},
           adaptix.ConsoleMessageData{}, nil
```

On the C side, they would be read using successive calls to `nax_read_lenstr()`.

---

## Step 4 — Register the Command in the UI (`ax_config.axs`)

The `ax_config.axs` file defines how the command appears in the Adaptix interface: name, description, arguments, and usage example.

### 4a. Create the command

```javascript
// Sintaxis:
// ax.create_command(name, description, example_use, loading_message)

let cmd_cat = ax.create_command(
    "cat",                      // Command name (must match the case in Go)
    "Read file contents",       // Description displayed in the UI
    "cat /etc/passwd",          // Usage example
    "Reading..."                // Message displayed while the command is running
);
```

### 4b. Declare the arguments

```javascript
// addArgString(name, mandatory, description)
cmd_cat.addArgString("path", true, "File path");
```

**Types of available arguments:**

| Method | Type | description |
|--------|------|-------------|
| `addArgString("name", required, "desc")` | String | Free-form text |
| `addArgInt("name", required, "desc")` | Integer | Integer |
| `addArgBool("flag", required, "desc")` | Boolean | True/false flag |
| `addArgFile("name", required, "desc")` | File | Local file selector |
| `addArgFlagString("-f", "name", required, "desc")` | Flag with a value | Argument in the form `-f value` |

In Go, arguments are accessed as follows:

```go
path, _ := args["path"].(string)

portF, _ := args["port"].(float64)
port := int(portF)

verbose, _ := args["-verbose"].(bool)

fileB64, _ := args["file"].(string)
```

### 4c. Add to the command group

At the end of `RegisterCommands()`, include the new command in the group:

```javascript
let group = ax.create_commands_group("NAX-Linux", [
    cmd_whoami, cmd_pwd, cmd_env,
    cmd_cd,
    cmd_ls, cmd_cat, cmd_mkdir, cmd_rmdir, cmd_rm,  // ← cmd_cat
    cmd_download, cmd_upload,
    cmd_shell,
    cmd_ps, cmd_kill,
    cmd_ifconfig,
    // ... resto
]);

return { commands_linux: group };
```

---

## Step 5 — (Optional) Control the Output Format in `pl_format.go`

The `pl_format.go` file determines how the result is displayed in the Adaptix console.

* If the result has **a single line** → it is displayed directly in `[+]`
* If it has **multiple lines** → `"Processing Command"` is displayed in `[+]`, and the full output is shown below


For commands with multi-line output (such as `cat`), add the `CMD_*` to the corresponding `case`:

```go
func formatResult(cmdId byte, rawText string) (displayText, clearText string) {
    rawText = strings.TrimRight(rawText, "\x00\n")

    switch cmdId {

    // Comandos con salida multi-línea
    case CMD_LS, CMD_PS_LIST, CMD_SHELL, CMD_PS_RUN,
        CMD_CAT, CMD_ENV, CMD_WHOAMI, CMD_DOWNLOAD,
        CMD_IFCONFIG, CMD_BOF_JOBS, CMD_BOF_ASYNC, CMD_BOF:
        // CMD_CAT está aquí ↑

        lines := strings.Split(strings.TrimSpace(rawText), "\n")
        if len(lines) <= 1 {
            return rawText, ""
        }
        return "Processing Command", rawText

    // Comandos con salida de una línea
    default:
        return rawText, ""
    }
}
```

---

## Complete Flow Summary with `cat`

```
Operator writes: cat /etc/passwd
        │
        ▼
ax_config.axs
  cmd_cat = ax.create_command("cat", ...)
  cmd_cat.addArgString("path", true, "File path")
        │
        ▼
pl_commands.go → CreateCommand()
  case "cat":
    path = args["path"]             → "/etc/passwd"
    return pathCmd(CMD_CAT, path)
        │
  pathCmd(0x18, "/etc/passwd") builds:
    data[0]   = 0x18               → cmd_id
    data[1:5] = 0x0C000000         → args_len = 12 bytes
    data[5:9] = 0x0B000000         → string len = 11
    data[9:]  = "/etc/passwd"      → string bytes
        │
        ▼
PackTasks() construye el frame wire:
    [task_id(4)][cmd_id=0x18(1)][args_len(4)][len(4)]["/etc/passwd"]
        │
        ▼ (AES encryption + TCP/HTTPS)
        │
nax_dispatch() in the C agent
  case NAX_CMD_CAT: return cmd_cat(a, t, out, out_len)
        │
        ▼
cmd_cat()
  path = args_to_str(t)            → "/etc/passwd"
  f = fopen("/etc/passwd", "rb")
  lee contenido → OutBuf ob
  *out = ob.buf, *out_len = ob.len
  return NAX_STATUS_OK
        │
        ▼ (AES encryption + TCP/HTTPS)
        │
ProcessData() → pl_results.go
  taskId, status, data = DecodeResultBody(body)
  cmdId = pendingCmdIds[taskId]    → CMD_CAT (0x18)
        │
        ▼
formatResult(CMD_CAT, rawText)
  → displayText = "Processing Command"
  → clearText   = contents of /etc/passwd
        │
        ▼
UI display:
  [+] Processing Command
      root:x:0:0:root:/root:/bin/bash
      daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
      ...
```

---

## Checklist for a New Command

* [ ] `nax_linux.h` — `#define NAX_CMD_NAME 0xXX` with a unique value
* [ ] `commands.c` — `cmd_name()` function implemented with the correct signature
* [ ] `commands.c` — `case NAX_CMD_NAME:` in `nax_dispatch()`
* [ ] `pl_commands.go` — `CMD_NAME byte = 0xXX` in the `const` block
* [ ] `pl_commands.go` — `case "name":` in `CreateCommand()` returning `TaskData`
* [ ] `ax_config.axs` — `cmd_name` declared with arguments and added to the group
* [ ] `pl_format.go` — (if multi-line) add `CMD_NAME` to the extended output case
* [ ] Rebuild the C agent: `make` in `nax_linux/`
* [ ] Rebuild the Go extender: `make` in the project root
