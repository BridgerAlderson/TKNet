package netutil

import (
	"encoding/binary"
	"testing"
)

func nbstatFixture(question bool) []byte {
	query := buildNBSTATPacket(0x1234)
	result := append([]byte(nil), query[:12]...)
	binary.BigEndian.PutUint16(result[2:4], 0x8400)
	binary.BigEndian.PutUint16(result[6:8], 1)
	if question {
		result = append(result, query[12:]...)
		result = append(result, 0xc0, 0x0c)
	} else {
		binary.BigEndian.PutUint16(result[4:6], 0)
		result = append(result, query[12:46]...)
	}
	header := make([]byte, 10)
	binary.BigEndian.PutUint16(header[:2], 0x21)
	binary.BigEndian.PutUint16(header[2:4], 1)
	binary.BigEndian.PutUint16(header[8:10], 1+36+46)
	result = append(result, header...)
	result = append(result, 2)
	for i, name := range []string{"WORKGROUP      ", "WORKSTATION    "} {
		entry := make([]byte, 18)
		copy(entry, name)
		flags := uint16(0x0400)
		if i == 0 {
			flags |= 0x8000
		}
		binary.BigEndian.PutUint16(entry[16:18], flags)
		result = append(result, entry...)
	}
	return append(result, make([]byte, 46)...)
}
func TestNBSTATValidation(t *testing.T) {
	for _, question := range []bool{false, true} {
		packet := nbstatFixture(question)
		name, err := parseNBSTATResponse(packet, 0x1234)
		if err != nil || name != "WORKSTATION" {
			t.Fatalf("question=%t name=%q err=%v", question, name, err)
		}
		// No truncated prefix may be accepted, even after a full first name.
		for size := 0; size < len(packet); size++ {
			if _, err := parseNBSTATResponse(packet[:size], 0x1234); err == nil {
				t.Fatalf("accepted prefix %d", size)
			}
		}
	}
	for _, tt := range []struct {
		name   string
		offset int
		value  uint16
	}{
		{"stale transaction", 0, 1}, {"query instead of response", 2, 0},
		{"truncated flag", 2, 0x8600}, {"error response", 2, 0x8403},
		{"wrong opcode", 2, 0xa400}, {"no answers", 6, 0}, {"multiple answers", 6, 2},
		{"wrong record type", 46, 0x20}, {"wrong class", 48, 2}, {"short RDATA", 54, 19},
	} {
		t.Run(tt.name, func(t *testing.T) {
			packet := nbstatFixture(false)
			binary.BigEndian.PutUint16(packet[tt.offset:tt.offset+2], tt.value)
			if _, err := parseNBSTATResponse(packet, 0x1234); err == nil {
				t.Fatal("accepted malformed response")
			}
		})
	}
}
func TestNBSTATNameSelection(t *testing.T) {
	packet := nbstatFixture(false)
	second := 57 + 18
	packet[second+15] = 0x20 // server-only host
	if name, err := parseNBSTATResponse(packet, 0x1234); err != nil || name != "WORKSTATION" {
		t.Fatalf("server name=%q err=%v", name, err)
	}
	binary.BigEndian.PutUint16(packet[second+16:second+18], 0x8400) // both are groups
	if name, err := parseNBSTATResponse(packet, 0x1234); err != nil || name != "" {
		t.Fatalf("group became hostname: %q %v", name, err)
	}
}
func TestNBSTATRejectsBadCompression(t *testing.T) {
	for _, pointer := range []uint16{0xc000, 0xc032, 0xc0ff} {
		packet := nbstatFixture(true)
		binary.BigEndian.PutUint16(packet[50:52], pointer)
		if _, err := parseNBSTATResponse(packet, 0x1234); err == nil {
			t.Fatalf("accepted pointer %x", pointer)
		}
	}
}
func FuzzNBSTATResponse(f *testing.F) {
	f.Add(nbstatFixture(false))
	f.Add(nbstatFixture(true))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, packet []byte) { parseNBSTATResponse(packet, 0x1234) })
}
