package main

import "strings"

// Rule: never set clearText == displayText — the UI prints both and
// that causes double output.
func formatResult(cmdId byte, rawText string) (displayText, clearText string) {
	rawText = strings.TrimRight(rawText, "\x00\n")

	switch cmdId {

	// Commands that produce multi-line/structured output:
	// show a generic marker on [+] and the full output below.
	case CMD_LS, CMD_PS_LIST, CMD_SHELL, CMD_PS_RUN,
		CMD_CAT, CMD_ENV, CMD_WHOAMI, CMD_DOWNLOAD,
		CMD_IFCONFIG, CMD_BOF_JOBS, CMD_BOF_ASYNC, CMD_BOF:

		lines := strings.Split(strings.TrimSpace(rawText), "\n")
		if len(lines) <= 1 {
			// Single-line output — no point splitting
			return rawText, ""
		}
		return "Processing Command", rawText

	// All other commands produce a single informational line.
	default:
		return rawText, ""
	}
}
