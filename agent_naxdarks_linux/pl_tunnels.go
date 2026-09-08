package main

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"sync"

	adaptix "github.com/Adaptix-Framework/axc2/v2"
)

/* ========= [ tunnel wire constants — must match nax_linux.h ] ========= */

const (
	cmdTunnelConnectTCP byte = 0x3E
	cmdTunnelWriteTCP   byte = 0x40
	cmdTunnelClose      byte = 0x42
	cmdTunnelReverse    byte = 0x43
	cmdTunnelAccept     byte = 0x44
	cmdTunnelPause      byte = 0x45
	cmdTunnelResume     byte = 0x46
	cmdTunnelBindTCP    byte = 0x47  // bind TCP tunnel (new in SDK v3)

	statusTunnel byte = 0x20
)

// tunnelBindAllMap: passes bind_all flag from command → tunnelReverse callback.
var tunnelBindAllMap sync.Map

// rportfwdTunnelIds: stores tunnelId per agent+lport so stop can close the socket.
var rportfwdTunnelIds sync.Map

/* ========= [ task builder ] ========= */

func tunnelTask(cmdId byte, args []byte) adaptix.TaskData {
	buf := make([]byte, 5+len(args))
	buf[0] = cmdId
	binary.LittleEndian.PutUint32(buf[1:5], uint32(len(args)))
	copy(buf[5:], args)
	return adaptix.TaskData{
		Type: adaptix.TASK_TYPE_PROXY_DATA,
		Data: buf,
		Sync: false,
	}
}

/* ========= [ TunnelCallbacks ] ========= */

func tunnelConnectTCP(channelId int64, tunnelType, addressType int, address string, port int) adaptix.TaskData {
	addrBytes := []byte(address)
	args := make([]byte, 4+4+4+len(addrBytes)+4)
	binary.LittleEndian.PutUint32(args[0:4], uint32(channelId))
	binary.LittleEndian.PutUint32(args[4:8], uint32(tunnelType))
	binary.LittleEndian.PutUint32(args[8:12], uint32(len(addrBytes)))
	copy(args[12:12+len(addrBytes)], addrBytes)
	binary.LittleEndian.PutUint32(args[12+len(addrBytes):], uint32(port))
	return tunnelTask(cmdTunnelConnectTCP, args)
}

func tunnelConnectUDP(channelId int64, tunnelType, addressType int, address string, port int) adaptix.TaskData {
	return adaptix.TaskData{} // UDP not supported
}

func tunnelWriteTCP(channelId int64, data []byte) adaptix.TaskData {
	args := make([]byte, 4+4+len(data))
	binary.LittleEndian.PutUint32(args[0:4], uint32(channelId))
	binary.LittleEndian.PutUint32(args[4:8], uint32(len(data)))
	copy(args[8:], data)
	return tunnelTask(cmdTunnelWriteTCP, args)
}

func tunnelWriteUDP(channelId int64, data []byte) adaptix.TaskData {
	return adaptix.TaskData{} // UDP not supported
}

func tunnelPause(channelId int64) adaptix.TaskData {
	args := make([]byte, 4)
	binary.LittleEndian.PutUint32(args[0:4], uint32(channelId))
	return tunnelTask(cmdTunnelPause, args)
}

func tunnelResume(channelId int64) adaptix.TaskData {
	args := make([]byte, 4)
	binary.LittleEndian.PutUint32(args[0:4], uint32(channelId))
	return tunnelTask(cmdTunnelResume, args)
}

func tunnelClose(channelId int64) adaptix.TaskData {
	args := make([]byte, 4)
	binary.LittleEndian.PutUint32(args[0:4], uint32(channelId))
	return tunnelTask(cmdTunnelClose, args)
}

func tunnelReverse(tunnelId int64, port int) adaptix.TaskData {
	bindAll := false
	if v, ok := tunnelBindAllMap.LoadAndDelete(tunnelId); ok {
		bindAll, _ = v.(bool)
	}
	return tunnelReverseEx(tunnelId, port, bindAll)
}

func tunnelReverseEx(tunnelId int64, port int, bindAll bool) adaptix.TaskData {
	args := make([]byte, 9)
	binary.LittleEndian.PutUint32(args[0:4], uint32(tunnelId))
	binary.LittleEndian.PutUint32(args[4:8], uint32(port))
	if bindAll {
		args[8] = 1
	}
	return tunnelTask(cmdTunnelReverse, args)
}

// tunnelBindTCP is called by the server when it wants the agent to set up a
// bind-mode TCP tunnel. addressType follows SOCKS5 ATYP conventions.
func tunnelBindTCP(channelId int64, addressType int, address string, port int) adaptix.TaskData {
	addrBytes := []byte(address)
	args := make([]byte, 4+4+4+len(addrBytes)+4)
	binary.LittleEndian.PutUint32(args[0:4], uint32(channelId))
	binary.LittleEndian.PutUint32(args[4:8], uint32(addressType))
	binary.LittleEndian.PutUint32(args[8:12], uint32(len(addrBytes)))
	copy(args[12:12+len(addrBytes)], addrBytes)
	binary.LittleEndian.PutUint32(args[12+len(addrBytes):], uint32(port))
	return tunnelTask(cmdTunnelBindTCP, args)
}

func rportfwdCloseTask(tunnelId int64) adaptix.TaskData {
	// Send cmdTunnelPause with the tunnelId — the agent interprets Pause
	// on an unknown channel_id as "close the rportfwd listener with this tunnel_id".
	// Must use TASK_TYPE_TUNNEL (not PROXY_DATA) so the server routes it
	// directly to the agent instead of treating it as pivot relay data.
	t := tunnelPause(tunnelId)
	t.Type   = adaptix.TASK_TYPE_TUNNEL
	t.TaskId = int64(rand.Int31()) | 1
	return t
}

func rportfwdKey(agentId int64, lport int) string {
	return fmt.Sprintf("%d:%d", agentId, lport)
}

/* ========= [ result parser — called from ProcessData for STATUS_TUNNEL ] ========= */

func processTunnelResult(agentId int64, data []byte) {
	off := 0
	for off+8 <= len(data) {
		entryLen := int(binary.LittleEndian.Uint32(data[off : off+4]))
		if entryLen < 4 || off+4+entryLen > len(data) {
			break
		}
		cmdId   := binary.LittleEndian.Uint32(data[off+4 : off+8])
		payload := data[off+8 : off+4+entryLen]

		switch byte(cmdId) {

		case cmdTunnelConnectTCP:
			if len(payload) < 12 { break }
			channelId := int(binary.LittleEndian.Uint32(payload[0:4]))
			result    := binary.LittleEndian.Uint32(payload[8:12])
			if Ts != nil {
				if result == 0 {
					Ts.TsTunnelConnectionResume(agentId, int64(channelId), false)
				} else {
					Ts.TsTunnelConnectionClose(int64(channelId), false)
				}
			}

		case cmdTunnelWriteTCP:
			if len(payload) < 8 { break }
			channelId := int(binary.LittleEndian.Uint32(payload[0:4]))
			dataLen   := int(binary.LittleEndian.Uint32(payload[4:8]))
			if len(payload) < 8+dataLen { break }
			if Ts != nil {
				Ts.TsTunnelConnectionData(int64(channelId), payload[8:8+dataLen])
			}

		case cmdTunnelClose:
			if len(payload) < 4 { break }
			channelId := int(binary.LittleEndian.Uint32(payload[0:4]))
			if Ts != nil {
				Ts.TsTunnelConnectionClose(int64(channelId), false)
			}

		case cmdTunnelReverse:
			if len(payload) < 12 { break }
			tunnelId := int(binary.LittleEndian.Uint32(payload[0:4]))
			result   := binary.LittleEndian.Uint32(payload[8:12])
			if Ts != nil {
				Ts.TsTunnelUpdateRportfwd(int64(tunnelId), result != 0)
			}

		case cmdTunnelAccept:
			if len(payload) < 8 { break }
			tunnelId    := int(binary.LittleEndian.Uint32(payload[0:4]))
			newChannelId := int(binary.LittleEndian.Uint32(payload[4:8]))
			if Ts != nil {
				Ts.TsTunnelConnectionAccept(int64(tunnelId), int64(newChannelId))
			}

		case cmdTunnelPause:
			if len(payload) < 4 { break }
			channelId := int(binary.LittleEndian.Uint32(payload[0:4]))
			if Ts != nil {
				Ts.TsTunnelPause(int64(channelId))
			}

		case cmdTunnelResume:
			if len(payload) < 4 { break }
			channelId := int(binary.LittleEndian.Uint32(payload[0:4]))
			if Ts != nil {
				Ts.TsTunnelResume(int64(channelId))
			}

		default:
			naxLogErr("tunnel: unknown cmdId 0x%02x", cmdId)
		}

		off += 4 + entryLen
	}
}
