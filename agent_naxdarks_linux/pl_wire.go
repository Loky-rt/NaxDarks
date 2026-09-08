package main

// extender/listener_naxdarks_http/pl_wire.go. See ADR-002.
//
// Implements the wire frame layout from docs/protocol/wire-v0.md:
//   +--------+----------+-------------------+------------------+
//   | type:1 | flags:1  | bodylen:4 (LE)    | body bytes       |
//   +--------+----------+-------------------+------------------+

import (
	"encoding/json"
	"fmt"
	"encoding/binary"
	"errors"
)

const (
	WireTypeRegister  byte = 0x01
	WireTypeHeartbeat byte = 0x02
	WireTypeResult    byte = 0x03
	WireTypeNoTasks   byte = 0x80
	WireTypeTask      byte = 0x81
	WireTypeProfile   byte = 0x82
)

func EncodeFrame(msgType byte, body []byte) []byte {
	out := make([]byte, 6+len(body))
	out[0] = msgType
	out[1] = 0
	binary.LittleEndian.PutUint32(out[2:6], uint32(len(body)))
	copy(out[6:], body)
	return out
}

func DecodeFrame(frame []byte) (byte, byte, []byte, error) {
	if len(frame) < 6 {
		return 0, 0, nil, errors.New("nax-wire: frame shorter than 6-byte header")
	}
	msgType := frame[0]
	flags := frame[1]
	bodyLen := int(binary.LittleEndian.Uint32(frame[2:6]))
	if 6+bodyLen > len(frame) {
		return 0, 0, nil, errors.New("nax-wire: body truncated relative to declared length")
	}
	return msgType, flags, frame[6 : 6+bodyLen], nil
}

type RegisterBody struct {
	Hostname string
	Username string
	Arch     byte
	Pid      uint32
	SleepMs  uint32
	Tid         uint32
	Ip          string
	Domain      string
	ProcessName string
	Elevated  byte
	OsMajor   uint32
	OsMinor   uint32
	OsBuild   uint16
	ParentPid uint32
	Acp       uint32
	OemCp     uint32
	ImgPath   string
}

func DecodeRegister(body []byte) (RegisterBody, error) {
	var r RegisterBody
	cursor := 0

	hostname, cursor, err := readLenPrefixedString(body, cursor)
	if err != nil {
		return r, err
	}
	r.Hostname = hostname

	username, cursor, err := readLenPrefixedString(body, cursor)
	if err != nil {
		return r, err
	}
	r.Username = username

	if cursor+1+4+4 > len(body) {
		return r, errors.New("nax-wire: REGISTER body truncated at fixed tail")
	}
	r.Arch = body[cursor]
	cursor++
	r.Pid = binary.LittleEndian.Uint32(body[cursor : cursor+4])
	cursor += 4
	r.SleepMs = binary.LittleEndian.Uint32(body[cursor : cursor+4])
	cursor += 4

	if cursor+4 <= len(body) {
		r.Tid = binary.LittleEndian.Uint32(body[cursor : cursor+4])
		cursor += 4
	}
	if cursor+2 <= len(body) {
		if ip, newCursor, ipErr := readLenPrefixedString(body, cursor); ipErr == nil {
			r.Ip = ip
			cursor = newCursor
		}
	}
	if cursor+2 <= len(body) {
		if domain, newCursor, domErr := readLenPrefixedString(body, cursor); domErr == nil {
			r.Domain = domain
			cursor = newCursor
		}
	}
	if cursor+2 <= len(body) {
		if proc, newCursor, procErr := readLenPrefixedString(body, cursor); procErr == nil {
			r.ProcessName = proc
			cursor = newCursor
		}
	}
	if cursor+1 <= len(body) {
		r.Elevated = body[cursor]
		cursor++
	}
	if cursor+4 <= len(body) {
		r.OsMajor = binary.LittleEndian.Uint32(body[cursor : cursor+4])
		cursor += 4
	}
	if cursor+4 <= len(body) {
		r.OsMinor = binary.LittleEndian.Uint32(body[cursor : cursor+4])
		cursor += 4
	}
	if cursor+2 <= len(body) {
		r.OsBuild = binary.LittleEndian.Uint16(body[cursor : cursor+2])
		cursor += 2
	}
	if cursor+4 <= len(body) {
		r.ParentPid = binary.LittleEndian.Uint32(body[cursor : cursor+4])
		cursor += 4
	}
	if cursor+4 <= len(body) {
		r.Acp = binary.LittleEndian.Uint32(body[cursor : cursor+4])
		cursor += 4
	}
	if cursor+4 <= len(body) {
		r.OemCp = binary.LittleEndian.Uint32(body[cursor : cursor+4])
		cursor += 4
	}
	if cursor+2 <= len(body) {
		if img, newCursor, imgErr := readLenPrefixedString(body, cursor); imgErr == nil {
			r.ImgPath = img
			cursor = newCursor
		}
	}
	_ = cursor
	return r, nil
}

func readLenPrefixedString(body []byte, cursor int) (string, int, error) {
	if cursor+2 > len(body) {
		return "", 0, errors.New("nax-wire: length-prefixed string: header truncated")
	}
	n := int(binary.LittleEndian.Uint16(body[cursor : cursor+2]))
	cursor += 2
	if cursor+n > len(body) {
		return "", 0, errors.New("nax-wire: length-prefixed string: body truncated")
	}
	s := string(body[cursor : cursor+n])
	cursor += n
	return s, cursor, nil
}

func EncodeTaskBody(taskId uint32, cmdData []byte) []byte {
	out := make([]byte, 4+len(cmdData))
	binary.LittleEndian.PutUint32(out[0:4], taskId)
	copy(out[4:], cmdData)
	return out
}

func DecodeResultBody(body []byte) (taskId uint32, status byte, data []byte, err error) {
	if len(body) < 9 {
		return 0, 0, nil, errors.New("nax-wire: RESULT body too short (need ≥9 bytes)")
	}
	taskId = binary.LittleEndian.Uint32(body[0:4])
	status = body[4]
	dataLen := int(binary.LittleEndian.Uint32(body[5:9]))
	if 9+dataLen > len(body) {
		return 0, 0, nil, errors.New("nax-wire: RESULT body data field truncated")
	}
	return taskId, status, body[9 : 9+dataLen], nil
}

func EncodeProfileBodyV1(getUris, postUris, userAgents, headers []string, cookieName string, rotation byte) []byte {
	var buf []byte

	writeStringList := func(strs []string) {
		b := make([]byte, 2)
		binary.LittleEndian.PutUint16(b, uint16(len(strs)))
		buf = append(buf, b...)
		for _, s := range strs {
			lb := make([]byte, 2)
			binary.LittleEndian.PutUint16(lb, uint16(len(s)))
			buf = append(buf, lb...)
			buf = append(buf, []byte(s)...)
		}
	}

	writeStringList(getUris)
	writeStringList(postUris)
	writeStringList(userAgents)
	writeStringList(headers)

	cb := make([]byte, 2)
	binary.LittleEndian.PutUint16(cb, uint16(len(cookieName)))
	buf = append(buf, cb...)
	buf = append(buf, []byte(cookieName)...)

	// rotation
	buf = append(buf, rotation)

	return buf
}

/* Profile v2 types */

type OutputConfig struct {
	Format    string
	Mask      bool
	Placement string
	Name      string
	Prepend   string
	Append    string
	EmptyResp string
}

type HTTPTransaction struct {
	URIs          []string
	ClientHeaders map[string]string
	ClientParams  map[string]string
	ClientMeta    OutputConfig
	ClientOutput  *OutputConfig
	ServerHeaders map[string]string
	ServerOutput  OutputConfig
}

type ServerError struct {
	Status  int
	Body    string
	Headers map[string]string
}

type ProfileConfig struct {
	Hosts          []string
	UserAgent      string
	Rotation       string
	BeaconIdHeader string
	Error          ServerError
	Get            HTTPTransaction
	Post           HTTPTransaction
}

/* Profile v2 wire helpers */

func writeLP(buf *[]byte, s string) {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, uint16(len(s)))
	*buf = append(*buf, b...)
	*buf = append(*buf, []byte(s)...)
}

func writeOutputConfig(buf *[]byte, cfg *OutputConfig) {
	formatMap := map[string]byte{"raw": 0, "base64": 1, "base64url": 2, "hex": 3}
	placementMap := map[string]byte{"body": 0, "header": 1, "cookie": 2, "parameter": 3}
	fmtByte := formatMap[cfg.Format]
	placeByte := placementMap[cfg.Placement]
	maskByte := byte(0)
	if cfg.Mask {
		maskByte = 1
	}
	*buf = append(*buf, fmtByte, maskByte, placeByte)
	writeLP(buf, cfg.Name)
	writeLP(buf, cfg.Prepend)
	writeLP(buf, cfg.Append)
	writeLP(buf, cfg.EmptyResp)
}

func writeStringList(buf *[]byte, strs []string) {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, uint16(len(strs)))
	*buf = append(*buf, b...)
	for _, s := range strs {
		writeLP(buf, s)
	}
}

func writeHeaderMap(buf *[]byte, hdrs map[string]string) {
	entries := make([]string, 0, len(hdrs))
	for k, v := range hdrs {
		entries = append(entries, k+": "+v)
	}
	writeStringList(buf, entries)
}

/* Profile v2 encoder */

func EncodeProfileBodyV2(p *ProfileConfig) []byte {
	var buf []byte
	buf = append(buf, 0x02) // version
	rot := byte(0)
	if p.Rotation == "random" {
		rot = 1
	}
	buf = append(buf, rot)

	writeLP(&buf, p.UserAgent)
	beaconHdr := p.BeaconIdHeader
	if beaconHdr == "" {
		beaconHdr = "X-Beacon-Id"
	}
	writeLP(&buf, beaconHdr)
	writeStringList(&buf, p.Hosts)

	// server error
	eb := make([]byte, 2)
	binary.LittleEndian.PutUint16(eb, uint16(p.Error.Status))
	buf = append(buf, eb...)
	writeLP(&buf, p.Error.Body)
	writeHeaderMap(&buf, p.Error.Headers)

	// GET block
	writeStringList(&buf, p.Get.URIs)
	writeOutputConfig(&buf, &p.Get.ClientMeta)
	writeHeaderMap(&buf, p.Get.ClientHeaders)
	// client params as "key=value" strings
	paramStrs := make([]string, 0, len(p.Get.ClientParams))
	for k, v := range p.Get.ClientParams {
		paramStrs = append(paramStrs, k+"="+v)
	}
	writeStringList(&buf, paramStrs)
	writeOutputConfig(&buf, &p.Get.ServerOutput)
	writeHeaderMap(&buf, p.Get.ServerHeaders)

	// POST block
	writeStringList(&buf, p.Post.URIs)
	writeOutputConfig(&buf, &p.Post.ClientMeta)
	postOutput := p.Post.ClientOutput
	if postOutput == nil {
		postOutput = &OutputConfig{Format: "raw", Placement: "body"}
	}
	writeOutputConfig(&buf, postOutput)
	writeHeaderMap(&buf, p.Post.ClientHeaders)
	writeOutputConfig(&buf, &p.Post.ServerOutput)
	writeHeaderMap(&buf, p.Post.ServerHeaders)

	return buf
}

// ParseProfileJSON parses a profile JSON file (same format as profiles/*.json) -- into a ProfileConfig suitable for EncodeProfileBodyV2.
func ParseProfileJSON(data []byte) (*ProfileConfig, error) {
	var raw struct {
		Callbacks []struct {
			Hosts          []string          `json:"hosts"`
			UserAgent      string            `json:"user_agent"`
			BeaconIdHeader string            `json:"beacon_id_header"`
			Rotation       string            `json:"rotation"`
			Error          struct {
				Status  int               `json:"status"`
				Body    string            `json:"body"`
				Headers map[string]string `json:"headers"`
			} `json:"server_error"`
			Get struct {
				URI    []string `json:"uri"`
				Client struct {
					Headers    map[string]string `json:"headers"`
					Metadata   OutputConfig      `json:"metadata"`
					Parameters map[string]string `json:"parameters"`
				} `json:"client"`
				Server struct {
					Headers map[string]string `json:"headers"`
					Output  OutputConfig      `json:"output"`
				} `json:"server"`
			} `json:"get"`
			Post struct {
				URI    []string `json:"uri"`
				Client struct {
					Headers    map[string]string `json:"headers"`
					Metadata   OutputConfig      `json:"metadata"`
					Output     OutputConfig      `json:"output"`
					Parameters map[string]string `json:"parameters"`
				} `json:"client"`
				Server struct {
					Headers map[string]string `json:"headers"`
					Output  OutputConfig      `json:"output"`
				} `json:"server"`
			} `json:"post"`
		} `json:"callbacks"`
	}

	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("json parse: %w", err)
	}
	if len(raw.Callbacks) == 0 {
		return nil, fmt.Errorf("no callbacks in profile")
	}

	cb := raw.Callbacks[0]
	p := &ProfileConfig{
		Hosts:          cb.Hosts,
		UserAgent:      cb.UserAgent,
		Rotation:       cb.Rotation,
		BeaconIdHeader: cb.BeaconIdHeader,
		Error: ServerError{
			Status:  cb.Error.Status,
			Body:    cb.Error.Body,
			Headers: cb.Error.Headers,
		},
		Get: HTTPTransaction{
			URIs:          cb.Get.URI,
			ClientHeaders: cb.Get.Client.Headers,
			ClientParams:  cb.Get.Client.Parameters,
			ClientMeta:    cb.Get.Client.Metadata,
			ServerHeaders: cb.Get.Server.Headers,
			ServerOutput:  cb.Get.Server.Output,
		},
		Post: HTTPTransaction{
			URIs:          cb.Post.URI,
			ClientHeaders: cb.Post.Client.Headers,
			ClientParams:  cb.Post.Client.Parameters,
			ClientMeta:    cb.Post.Client.Metadata,
			ClientOutput:  &cb.Post.Client.Output,
			ServerHeaders: cb.Post.Server.Headers,
			ServerOutput:  cb.Post.Server.Output,
		},
	}

	return p, nil
}
