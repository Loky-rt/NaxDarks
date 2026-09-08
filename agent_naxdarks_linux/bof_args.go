package main

import (
	"encoding/binary"
	"fmt"
)

type BofPacker struct {
	buf []byte
}

func NewBofPacker() *BofPacker {
	return &BofPacker{}
}

func (p *BofPacker) AddStr(s string) {
	b := []byte(s)
	ln := make([]byte, 4)
	binary.LittleEndian.PutUint32(ln, uint32(len(b)+1))
	p.buf = append(p.buf, ln...)
	p.buf = append(p.buf, b...)
	p.buf = append(p.buf, 0x00)
}

func (p *BofPacker) AddWStr(s string) {
	runes := []rune(s)
	wide := make([]byte, (len(runes)+1)*2)
	for i, r := range runes {
		wide[i*2] = byte(r & 0xFF)
		wide[i*2+1] = byte((r >> 8) & 0xFF)
	}
	ln := make([]byte, 4)
	binary.LittleEndian.PutUint32(ln, uint32(len(wide)))
	p.buf = append(p.buf, ln...)
	p.buf = append(p.buf, wide...)
}

func (p *BofPacker) AddInt(v int32) {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(v))
	p.buf = append(p.buf, b...)
}

func (p *BofPacker) AddShort(v int16) {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, uint16(v))
	p.buf = append(p.buf, b...)
}

func (p *BofPacker) AddBin(data []byte) {
	ln := make([]byte, 4)
	binary.LittleEndian.PutUint32(ln, uint32(len(data)))
	p.buf = append(p.buf, ln...)
	p.buf = append(p.buf, data...)
}

// Bytes returns the packed buffer WITH 4-byte total-length prefix.
// BeaconDataParse skips these first 4 bytes (CS convention).
func (p *BofPacker) Bytes() []byte {
	prefix := make([]byte, 4)
	binary.LittleEndian.PutUint32(prefix, uint32(len(p.buf)))
	return append(prefix, p.buf...)
}

func packBofArgs(spec string) ([]byte, error) {
	if spec == "" {
		return nil, nil
	}
	packer := NewBofPacker()
	for _, part := range splitBofArgs(spec) {
		idx := 0
		for idx < len(part) && part[idx] != ':' {
			idx++
		}
		var typ, val string
		if idx >= len(part) {
			typ = "str"
			val = part
		} else {
			typ = part[:idx]
			val = part[idx+1:]
		}
		switch typ {
		case "str":
			packer.AddStr(val)
		case "wstr":
			packer.AddWStr(val)
		case "int":
			var n int64
			if _, err := fmt.Sscan(val, &n); err != nil {
				return nil, fmt.Errorf("int arg %q: %w", val, err)
			}
			packer.AddInt(int32(n))
		case "short":
			var n int64
			if _, err := fmt.Sscan(val, &n); err != nil {
				return nil, fmt.Errorf("short arg %q: %w", val, err)
			}
			packer.AddShort(int16(n))
		default:
			return nil, fmt.Errorf("unknown arg type %q", typ)
		}
	}
	return packer.Bytes(), nil
}

func splitBofArgs(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}
