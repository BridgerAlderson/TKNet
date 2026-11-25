package scanner

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
	"unicode/utf16"
)

// These fixtures are protocol messages, not fake smbSession.ListShares
// results: production bind, framing, NDR parsing and pagination all execute.
type enumFixturePipe struct {
	t        *testing.T
	replies  [][][]byte
	messages [][]byte
	writes   [][]byte
	readSize int
}

func (p *enumFixturePipe) Write(b []byte) (int, error) {
	p.t.Helper()
	if len(p.messages) != 0 {
		p.t.Fatal("new RPC request before consuming the previous response")
	}
	p.writes = append(p.writes, append([]byte(nil), b...))
	index := len(p.writes) - 1
	if index >= len(p.replies) {
		return 0, errors.New("unexpected extra RPC request")
	}
	for _, reply := range p.replies[index] {
		p.messages = append(p.messages, append([]byte(nil), reply...))
	}
	return len(b), nil
}

func (p *enumFixturePipe) Read(b []byte) (int, error) {
	p.t.Helper()
	if len(p.messages) == 0 {
		return 0, io.EOF
	}
	// Reproduce a message-mode pipe's rejection of an undersized buffer:
	// consuming the 16-byte RPC header directly must not happen.
	if len(b) < len(p.messages[0]) {
		return 0, errors.New("STATUS_BUFFER_OVERFLOW: caller discarded pipe payload")
	}
	n := len(p.messages[0])
	if p.readSize > 0 {
		n = min(n, p.readSize)
	}
	copy(b, p.messages[0][:n])
	p.messages[0] = p.messages[0][n:]
	if len(p.messages[0]) == 0 {
		p.messages = p.messages[1:]
	}
	return n, nil
}

func fixturePut32(b *[]byte, values ...uint32) {
	for _, value := range values {
		*b = binary.LittleEndian.AppendUint32(*b, value)
	}
}

func fixtureRPC(kind, flags byte, call uint32, body []byte) []byte {
	header := []byte{5, 0, kind, flags, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	binary.LittleEndian.PutUint16(header[8:10], uint16(16+len(body)))
	binary.LittleEndian.PutUint32(header[12:16], call)
	return append(header, body...)
}

func fixtureBindAck() []byte {
	// Bind acknowledgement with secondary address "\\pipe\\srvsvc\0",
	// one accepted context and the NDR32 v2 transfer syntax.
	body := []byte{0xb8, 0x10, 0xb8, 0x10, 0, 0, 0, 0}
	addr := []byte("\\pipe\\srvsvc\x00")
	body = binary.LittleEndian.AppendUint16(body, uint16(len(addr)))
	body = append(body, addr...)
	for len(body)%4 != 0 {
		body = append(body, 0)
	}
	body = append(body, 1, 0, 0, 0, 0, 0, 0, 0)
	body = append(body, 0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60)
	fixturePut32(&body, 2)
	return fixtureRPC(12, 3, 1, body)
}

func fixtureNDRText(b *[]byte, text string) {
	units := append(utf16.Encode([]rune(text)), 0)
	fixturePut32(b, uint32(len(units)), 0, uint32(len(units)))
	for _, unit := range units {
		*b = binary.LittleEndian.AppendUint16(*b, unit)
	}
	for len(*b)%4 != 0 {
		*b = append(*b, 0)
	}
}

func fixtureSharePage(names []string, total, resume, status uint32) []byte {
	var b []byte
	fixturePut32(&b, 1, 1, 0x20000, uint32(len(names)))
	if names == nil {
		fixturePut32(&b, 0)
	} else {
		fixturePut32(&b, 0x20004, uint32(len(names)))
		for i := range names {
			commentPointer := uint32(0)
			if i%2 == 0 {
				commentPointer = uint32(0x30004 + i*8)
			}
			fixturePut32(&b, uint32(0x30000+i*8), 0, commentPointer)
		}
		for i, name := range names {
			fixtureNDRText(&b, name)
			if i%2 == 0 {
				fixtureNDRText(&b, "Notes for Łódź staff")
			}
		}
	}
	fixturePut32(&b, total, 0x40000, resume, status)
	return b
}

func fixtureResponse(call uint32, stub []byte, fragmentBytes int) [][]byte {
	var messages [][]byte
	for offset := 0; offset < len(stub); {
		n := min(fragmentBytes, len(stub)-offset)
		flags := byte(0)
		if offset == 0 {
			flags |= 1
		}
		if offset+n == len(stub) {
			flags |= 2
		}
		body := make([]byte, 8)
		// Allocation hint is a hint, not a substitute for FIRST/LAST flags.
		binary.LittleEndian.PutUint32(body, uint32(len(stub)-offset))
		body = append(body, stub[offset:offset+n]...)
		messages = append(messages, fixtureRPC(2, flags, call, body))
		offset += n
	}
	return messages
}

func fixturePipe(t *testing.T, pages ...[]byte) *enumFixturePipe {
	t.Helper()
	p := &enumFixturePipe{t: t, replies: [][][]byte{{fixtureBindAck()}}}
	for i, page := range pages {
		p.replies = append(p.replies, fixtureResponse(uint32(i+2), page, 277))
	}
	return p
}

func TestSMBEnumerationFragmentedPaginated(t *testing.T) {
	var wanted []string
	for i := 0; i < 720; i++ {
		wanted = append(wanted, fmt.Sprintf("Bölüm-%03d-財務-📁$", i))
	}
	pages := [][]string{wanted[:240], append([]string{wanted[239]}, wanted[240:480]...), wanted[480:]}
	p := fixturePipe(t,
		fixtureSharePage(pages[0], 720, 239, 234),
		fixtureSharePage(pages[1], 480, 479, 234),
		fixtureSharePage(pages[2], 240, 0, 0))
	p.readSize = 37 // split headers and UTF-16 strings across arbitrary reads
	got, err := enumerateSMBShares(p, "192.0.2.5")
	if err != nil || !reflect.DeepEqual(fixtureListedNames(got), wanted) {
		t.Fatalf("got %d shares, err=%v; want all %d in server order", len(got), err, len(wanted))
	}
	if len(p.writes) != 4 {
		t.Fatalf("got %d requests, want bind and three enumeration calls", len(p.writes))
	}
	for i, request := range p.writes[1:] {
		if request[2] != 0 || binary.LittleEndian.Uint16(request[22:24]) != 15 {
			t.Fatal("not a NetrShareEnum request")
		}
		if binary.LittleEndian.Uint32(request[12:16]) != uint32(i+2) {
			t.Fatal("call IDs did not advance")
		}
		tail := request[len(request)-32:]
		if !reflect.DeepEqual(tail[:28], []byte{
			1, 0, 0, 0, 1, 0, 0, 0, 4, 0, 2, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 255, 255, 255, 255, 8, 0, 2, 0,
		}) {
			t.Fatal("wrong NDR32 level/container/preferred-length/resume request")
		}
		wantResume := []uint32{0, 239, 479}[i]
		if binary.LittleEndian.Uint32(tail[28:]) != wantResume {
			t.Fatalf("request %d lost server resume handle", i)
		}
	}
}

func TestSMBEnumerationEmptyAndCaseDuplicates(t *testing.T) {
	for _, names := range [][]string{nil, {}, {"DATA", "data", "資料"}} {
		p := fixturePipe(t, fixtureSharePage(names, uint32(len(names)), 0, 0))
		got, err := enumerateSMBShares(p, "server")
		if err != nil {
			t.Fatal(err)
		}
		want := names
		if len(names) == 3 {
			want = []string{"DATA", "資料"}
		}
		if strings.Join(fixtureListedNames(got), "|") != strings.Join(want, "|") {
			t.Fatalf("got %v, want %q", got, want)
		}
	}
}

func TestSMBEnumerationTotalAndCapabilityFlags(t *testing.T) {
	for _, total := range []uint32{1, 2, 3} {
		p := fixturePipe(t,
			fixtureSharePage([]string{"First"}, 2, 1, 234),
			fixtureSharePage([]string{"Last"}, total, 0, 0))
		p.replies[0][0][3] |= 0x14 // header-signing support, multiplexing
		for _, reply := range p.replies[1:] {
			for _, fragment := range reply {
				fragment[3] |= 0x14 // pending cancel, multiplexing
			}
		}
		got, err := enumerateSMBShares(p, "server")
		if !reflect.DeepEqual(fixtureListedNames(got), []string{"First", "Last"}) || (err != nil) != (total > 2) {
			t.Fatalf("total=%d, names=%v, err=%v", total, got, err)
		}
	}
	p := fixturePipe(t, fixtureSharePage([]string{"First"}, 2, 0, 0))
	if got, err := enumerateSMBShares(p, "server"); len(got) != 1 || err == nil {
		t.Fatalf("single-page truncation was hidden: names=%v err=%v", got, err)
	}
}

func TestSMBEnumerationPreservesPagesOnFailure(t *testing.T) {
	for _, tc := range []struct {
		name   string
		second []byte
		want   []string
	}{
		{"access denied", fixtureSharePage(nil, 0, 0, 5), []string{"First"}},
		{"partial access denied", fixtureSharePage([]string{"Second"}, 1, 0, 5), []string{"First", "Second"}},
		{"missing resume", fixtureSharePage([]string{"Second"}, 2, 0, 234), []string{"First", "Second"}},
		{"repeated resume", fixtureSharePage([]string{"Second"}, 2, 9, 234), []string{"First", "Second"}},
		{"empty continuing page", fixtureSharePage(nil, 2, 10, 234), []string{"First"}},
		{"truncated NDR", []byte{1, 0, 0, 0}, []string{"First"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := fixturePipe(t, fixtureSharePage([]string{"First"}, 3, 9, 234), tc.second)
			got, err := enumerateSMBShares(p, "server")
			if err == nil || !reflect.DeepEqual(fixtureListedNames(got), tc.want) {
				t.Fatalf("got %v, err=%v", got, err)
			}
		})
	}
}

func TestSMBEnumerationRPCValidation(t *testing.T) {
	page := fixtureSharePage([]string{"Data"}, 1, 0, 0)
	good := fixtureResponse(2, page, 4000)[0]
	for _, tc := range []struct {
		name   string
		change func([]byte) []byte
	}{
		{"wrong call", func(p []byte) []byte { p[12] = 7; return p }},
		{"wrong version", func(p []byte) []byte { p[0] = 4; return p }},
		{"big endian", func(p []byte) []byte { p[4] = 0; return p }},
		{"auth trailer", func(p []byte) []byte { p[10] = 4; return p }},
		{"short length", func(p []byte) []byte { p[8], p[9] = 8, 0; return p }},
		{"oversized fragment", func(p []byte) []byte { p[8], p[9] = 255, 255; return p }},
		{"missing first", func(p []byte) []byte { p[3] = 2; return p }},
		{"missing last", func(p []byte) []byte { p[3] = 1; return p }},
		{"did not execute", func(p []byte) []byte { p[3] |= 0x20; return p }},
		{"wrong context", func(p []byte) []byte { p[20] = 1; return p }},
		{"truncated message", func(p []byte) []byte { return p[:len(p)-1] }},
		{"fault", func(p []byte) []byte {
			body := make([]byte, 16)
			binary.LittleEndian.PutUint32(body[8:], 0x1c010002)
			return fixtureRPC(3, 3, 2, body)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := fixturePipe(t)
			p.replies = append(p.replies, [][]byte{tc.change(append([]byte(nil), good...))})
			if _, err := enumerateSMBShares(p, "server"); err == nil {
				t.Fatal("malformed RPC response accepted")
			}
		})
	}
	t.Run("repeated FIRST flag", func(t *testing.T) {
		p := fixturePipe(t)
		messages := fixtureResponse(2, page, 30)
		messages[1][3] |= 1
		p.replies = append(p.replies, messages)
		if _, err := enumerateSMBShares(p, "server"); err == nil {
			t.Fatal("repeated FIRST fragment accepted")
		}
	})
}

func TestSMBEnumerationBindValidation(t *testing.T) {
	for _, change := range []func([]byte){
		func(p []byte) { p[2] = 13 },
		func(p []byte) { p[3] = 1 },
		func(p []byte) { p[24], p[25] = 255, 255 },
		func(p []byte) { p[len(p)-24] = 2 },
		func(p []byte) { p[len(p)-20] ^= 255 },
		func(p []byte) { p[len(p)-4] = 3 },
	} {
		ack := fixtureBindAck()
		change(ack)
		p := &enumFixturePipe{t: t, replies: [][][]byte{{ack}}}
		if _, err := enumerateSMBShares(p, "server"); err == nil {
			t.Fatal("invalid bind acknowledgement accepted")
		}
		if len(p.writes) != 1 {
			t.Fatal("enumerated without an accepted RPC context")
		}
	}
}

func TestSMBEnumerationNDRValidation(t *testing.T) {
	good := fixtureSharePage([]string{"Data"}, 1, 0, 0)
	for _, tc := range []struct {
		name   string
		offset int
		value  uint32
	}{
		{"wrong level", 0, 2},
		{"wrong union arm", 4, 2},
		{"too many entries", 12, 0xffffffff},
		{"missing array", 16, 0},
		{"array mismatch", 20, 2},
		{"missing name pointer", 24, 0},
		{"huge string maximum", 36, 0xffffffff},
		{"nonzero string offset", 40, 1},
		{"string exceeds maximum", 44, 6},
		{"empty varying string", 44, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := append([]byte(nil), good...)
			binary.LittleEndian.PutUint32(b[tc.offset:], tc.value)
			if _, err := decodeSMBSharePage(b); err == nil {
				t.Fatal("malformed NDR response accepted")
			}
		})
	}
	for n := 0; n < len(good); n++ {
		if _, err := decodeSMBSharePage(good[:n]); err == nil {
			t.Fatalf("truncated NDR response length %d accepted", n)
		}
	}
	for _, data := range [][]byte{
		append(append([]byte(nil), good...), 0, 0, 0, 0),
		fixtureSharePage([]string{""}, 1, 0, 0),
		fixtureSharePage([]string{"a\x00b"}, 1, 0, 0),
	} {
		if _, err := decodeSMBSharePage(data); err == nil {
			t.Fatal("invalid string or trailing data accepted")
		}
	}
	invalidUTF := append([]byte(nil), good...)
	binary.LittleEndian.PutUint16(invalidUTF[48:], 0xd800)
	if _, err := decodeSMBSharePage(invalidUTF); err == nil {
		t.Fatal("unpaired UTF-16 surrogate accepted")
	}
}

func TestSMBEnumerationWireRequest(t *testing.T) {
	request, err := smbRPCEnumRequest(2, "server", 123)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(request, []byte{'\\', 0, '\\', 0, 's', 0, 'e', 0, 'r', 0, 'v', 0, 'e', 0, 'r', 0, 0, 0}) {
		t.Fatal("server name was not a terminated Unicode UNC name")
	}
	for _, host := range []string{"", "bad\x00name", strings.Repeat("x", 1025)} {
		if _, err := smbRPCEnumRequest(2, host, 0); err == nil {
			t.Fatal("invalid server name accepted")
		}
	}
}

// Generated independently with impacket.dcerpc.v5.srvs.NetrShareEnumResponse,
// level 1, two SHARE_INFO_1 entries ("Public", "資料$"), NULL remarks,
// total 2, resume 0, status 0. Preserve its nonzero referents and 0xab padding;
// this fixture must not depend on our encoder helpers or require Python at run time.
func TestSMBEnumerationIndependentNDRFixture(t *testing.T) {
	stub, err := hex.DecodeString("0100000001000000018b000002000000749c000002000000742c00000000000000000000c0b7000000000000000000000700000000000000070000005000750062006c00690063000000abab040000000000000004000000c78c99652400000002000000221800000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	page, err := decodeSMBSharePage(stub)
	if err != nil || !reflect.DeepEqual(fixtureListedNames(page.shares), []string{"Public", "資料$"}) || page.total != 2 || page.resume != 0 || page.status != 0 {
		t.Fatalf("independent NDR32 fixture failed: %+v, %v", page, err)
	}
}

func FuzzSMBSharePageDecoder(f *testing.F) {
	f.Add(fixtureSharePage(nil, 0, 0, 0))
	f.Add(fixtureSharePage([]string{"Data", "資料"}, 2, 0, 0))
	f.Fuzz(func(t *testing.T, stub []byte) {
		_, _ = decodeSMBSharePage(stub)
	})
}
