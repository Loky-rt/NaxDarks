package main

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	adaptix "github.com/Adaptix-Framework/axc2/v2"
)
// ProcessData is called by the teamserver for every decrypted frame from the agent.
func ProcessData(agentData adaptix.AgentData, decryptedData []byte) error {
	msgType, _, body, err := DecodeFrame(decryptedData)
	if err != nil {
		naxLogErr("ProcessData: DecodeFrame error: %v", err)
		return err
	}

	switch msgType {

	case WireTypeHeartbeat:
		return nil

	case WireTypeRegister:
		// Auto-register this host as a target in the C2
		if Ts != nil {
			_, _ = Ts.TsTargetsCreateAlive(agentData)
		}
		return nil

	case WireTypeResult:
		taskId, status, data, parseErr := DecodeResultBody(body)
		if parseErr != nil {
			naxLogErr("ProcessData: DecodeResultBody error: %v", parseErr)
			return parseErr
		}

		// taskId=0, status=statusTunnel → tunnel result
		if taskId == 0 && status == statusTunnel && len(data) > 0 {
			processTunnelResult(agentData.Id, data)
			return nil
		}

		// taskId=0 → synthetic pivot result from process_pivots()
		// Format: [PIV_TYPE(1)][pivot_id(4LE)][msg_len(4LE)][child_data]
		if taskId == 0 && len(data) >= 2 {
			pivType := data[0]
			switch pivType {
			case 0: // PIV_TYPE_DATA
				if len(data) < 9 {
					return nil
				}
				pivotId     := fmt.Sprintf("%08x", binary.LittleEndian.Uint32(data[1:5]))
				pivotDataLen := binary.LittleEndian.Uint32(data[5:9])
				if uint32(len(data)-9) >= pivotDataLen && Ts != nil {
					pivotData := data[9 : 9+pivotDataLen]
					_, _, childAgentId := Ts.TsGetPivotInfoById(pivotId)
					_ = Ts.TsAgentProcessData(childAgentId, pivotData)
					_ = Ts.TsAgentSetTick(childAgentId, "")
				}
			case 1: // PIV_TYPE_UNLINK
				if len(data) < 6 {
					return nil
				}
				pivotId     := fmt.Sprintf("%08x", binary.LittleEndian.Uint32(data[1:5]))
				pivotType   := data[5]
				if Ts != nil && pivotType != 0 {
					_, parentId, childId := Ts.TsGetPivotInfoById(pivotId)
					_ = Ts.TsPivotDelete(pivotId)
					Ts.TsAgentConsoleOutput(agentData.Id, "", adaptix.MESSAGE_SUCCESS,
						fmt.Sprintf("TCP pivot %s disconnected (child=%d)", pivotId, childId), "\n", true)
					Ts.TsAgentConsoleOutput(childId, "", adaptix.MESSAGE_SUCCESS,
						fmt.Sprintf(" ----- TCP agent disconnected from [%d] ----- ", parentId), "\n", true)
				}
			}
			return nil
		}

		taskIdStr  := fmt.Sprintf("%08x", taskId)

		// Peek at cmdId first to decide whether to keep the entry in the map.
		// CMD_DOWNLOAD is multi-result (START → CONTINUE… → FINISH) so we must
		// NOT delete the entry until the FINISH sub-frame arrives.
		cmdIdRaw, hasCmdId := pendingCmdIds.Load(taskIdStr)
		isDownloadFinish := false
		if hasCmdId {
			if b, ok := cmdIdRaw.(byte); ok && b == CMD_DOWNLOAD && len(data) >= 1 && data[0] == 0x03 {
				isDownloadFinish = true
			}
		}
		if hasCmdId && (isDownloadFinish || func() bool {
			b, ok := cmdIdRaw.(byte)
			return ok && b != CMD_DOWNLOAD
		}()) {
			pendingCmdIds.Delete(taskIdStr)
		}

		// If this result is from a profile_update, save the profile to store now.
		// The agent has received the profile and will apply it on next heartbeat.
		if hasCmdId {
			cmdIdByte, _ := cmdIdRaw.(byte)
			if cmdIdByte == CMD_PROFILE_UPDATE {
				agentUID := string(agentData.UID)
				if profileCfg, ok := pendingProfiles.LoadAndDelete(agentUID); ok {
					if pc, ok2 := profileCfg.(*ProfileConfig); ok2 {
						_ = saveProfileToStore(agentUID, pc)
					}
				}
			}
		}

		rawText := strings.TrimRight(string(data), "\x00")
		var displayText, clearText string
		if status == STATUS_ERR {
			displayText = fmt.Sprintf("[-] Error: %s", rawText)
			clearText   = ""
		} else if hasCmdId {
			displayText, clearText = formatResult(cmdIdRaw.(byte), rawText)
		} else {
			displayText = rawText
			clearText   = ""
		}

		if hasCmdId && status == STATUS_OK {
			cmdId := cmdIdRaw.(byte)
			switch cmdId {

			case CMD_SLEEP:
				// Result: [sleep_ms(4 LE)][jitter_pct(1)][text...]
				if len(data) >= 5 {
					sleepMs   := binary.LittleEndian.Uint32(data[0:4])
					jitterPct := uint(data[4])
					displayText = string(data[5:])
					if Ts != nil {
						updated        := agentData
						updated.Sleep  = uint(sleepMs / 1000)
						updated.Jitter = jitterPct
						_ = Ts.TsAgentUpdateData(updated)
					}
				}

			case CMD_DOWNLOAD:
				// Chunked download protocol:
				// START:    [0x01][file_id(4LE)][file_size(4LE)][name_len(4LE)][name]
				// CONTINUE: [0x02][file_id(4LE)][chunk_bytes]
				// FINISH:   [0x03][file_id(4LE)]
				clearText = ""
				if len(data) < 1 {
					displayText = "Download: empty result"
					break
				}
				sub := data[0]
				switch sub {
				case 0x01: // START — register transfer
					if len(data) < 13 {
						displayText = "Download: malformed START"
						break
					}
					fileId   := int64(binary.LittleEndian.Uint32(data[1:5]))
					fileSize := int64(binary.LittleEndian.Uint32(data[5:9]))
					nameLen  := int(binary.LittleEndian.Uint32(data[9:13]))
					if len(data) < 13+nameLen {
						displayText = "Download: malformed START (name)"
						break
					}
					filename := string(data[13 : 13+nameLen])
					if err := Ts.TsDownloadAdd(agentData.Id, fileId, filename, fileSize); err != nil {
						displayText = fmt.Sprintf("Download: TsDownloadAdd: %v", err)
					} else {
						displayText = fmt.Sprintf("Download started: %s (%d bytes)", filename, fileSize)
					}

				case 0x02: // CONTINUE — append chunk
					if len(data) < 5 {
						displayText = "Download: malformed CONTINUE"
						break
					}
					fileId    := int64(binary.LittleEndian.Uint32(data[1:5]))
					chunkData := data[5:]
					_ = Ts.TsDownloadUpdate(fileId, adaptix.TRANSFER_STATE_RUNNING, chunkData)
					displayText = fmt.Sprintf("Download chunk: +%d bytes", len(chunkData))

				case 0x03: // FINISH — close transfer
					if len(data) < 5 {
						displayText = "Download: malformed FINISH"
						break
					}
					fileId := int64(binary.LittleEndian.Uint32(data[1:5]))
					_ = Ts.TsDownloadClose(fileId, adaptix.TRANSFER_STATE_FINISHED)
					displayText = "Download complete"

				default:
					displayText = fmt.Sprintf("Download: unknown sub=0x%02x", sub)
				}

			case CMD_DOWNLOAD_CANCEL:
				clearText = ""
				displayText = rawText

			case CMD_LINK:
				// data: link_type(1) | wm(4LE) | aes_key(16) | sessionId(16) | encrypted_register
				if len(data) >= 37 { // 1+4+16+16 minimum
					linkType := data[0]
					watermark := fmt.Sprintf("%08x", binary.LittleEndian.Uint32(data[1:5]))
					beat := data[5:] // aes_key(16) + sessionId(16) + encrypted_register

					naxLogInfo("CMD_LINK: parent=%d linkType=%d wm=%s beatLen=%d",
						agentData.Id, linkType, watermark, len(beat))

					childAgentId, linkErr := Ts.TsListenerInteralHandler(watermark, beat)
					if linkErr != nil {
						naxLogErr("CMD_LINK: TsListenerInteralHandler wm=%s: %v", watermark, linkErr)
						displayText = fmt.Sprintf("link: server error: %v", linkErr)
					} else if childAgentId != 0 {
						_ = Ts.TsPivotCreate(taskIdStr, agentData.Id, childAgentId, "", false)
						// Clear "Unlink" mark set by TsPivotDelete on previous disconnect
						emptyMark := ""
						_ = Ts.TsAgentUpdateDataPartial(childAgentId, struct {
							Mark *string `json:"mark"`
						}{Mark: &emptyMark})
						if linkType == 2 {
							displayText = fmt.Sprintf("----- New TCP pivot agent: [%d]===[%d] (pivot: %s) -----",
								agentData.Id, childAgentId, taskIdStr)
							Ts.TsAgentConsoleOutput(childAgentId, "", adaptix.MESSAGE_SUCCESS, displayText, "\n", true)
						}
					} else {
						displayText = "link: failed — listener returned empty agent ID"
					}
					clearText = displayText
				}

			case CMD_UNLINK:
				// data: pivot_id(4LE) | pivot_type(1)
				if len(data) >= 5 {
					pivotId   := fmt.Sprintf("%08x", binary.LittleEndian.Uint32(data[0:4]))
					pivotType := data[4]
					_, parentId, childId := Ts.TsGetPivotInfoById(pivotId)
					if pivotType != 0 {
						_ = Ts.TsPivotDelete(pivotId)
						pivotLabel := "TCP"
						displayText = fmt.Sprintf("%s pivot %s disconnected (child=%d)", pivotLabel, pivotId, childId)
						Ts.TsAgentConsoleOutput(childId, "", adaptix.MESSAGE_SUCCESS,
							fmt.Sprintf(" ----- TCP agent disconnected from [%d] ----- ", parentId), "\n", true)
					} else {
						displayText = fmt.Sprintf("unlink %s: pivot not found", pivotId)
					}
					clearText = displayText
				}
			}
		}

		// Complete the task in the UI
		task := adaptix.TaskData{
			Type:       adaptix.TASK_TYPE_TASK,
			AgentId:    agentData.Id,
			TaskId:     int64(taskId),
			Completed:  true,
			FinishDate: time.Now().Unix(),
			Sync:       true,
		}
		if status == STATUS_ERR {
			task.MessageType = adaptix.MESSAGE_ERROR
			task.Message     = displayText
		} else {
			task.MessageType = adaptix.MESSAGE_SUCCESS
			task.Message     = displayText
			task.ClearText   = clearText
		}
		Ts.TsTaskUpdate(agentData.Id, task)
		return nil

	default:
		naxLogErr("ProcessData: unknown frame type 0x%02x", msgType)
		return nil
	}
}



func readLenPrefixedStringGo(buf []byte, offset int) (string, int) {
	if offset+4 > len(buf) {
		return "", offset
	}
	l := int(binary.LittleEndian.Uint32(buf[offset:]))
	offset += 4
	if offset+l > len(buf) {
		return "", offset
	}
	return string(buf[offset : offset+l]), offset + l
}
