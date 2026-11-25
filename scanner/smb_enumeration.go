package scanner

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"unicode/utf16"
)

// SRVSVC NetrShareEnum, NDR32 level 1. The pipe belongs to an already
// authenticated SMB session; enumeration never creates another session.
// Wire formats: MS-SRVS 2.2.4.23/2.2.4.24/2.2.4.38 and 3.1.4.8,
// MS-RPCE connection-oriented PDUs and C706 NDR constructed types.
const (
	smbRPCFragmentSize = 4280
	smbRPCMaxResponse  = 32 * 1024 * 1024
	smbRPCMaxShares    = 65536
	smbRPCMaxPages     = 4096
	smbRPCMoreData     = 234
)

var (
	smbRPCByteOrder = binary.LittleEndian
	smbSRVSVCUUID   = [16]byte{0xc8, 0x4f, 0x32, 0x4b, 0x70, 0x16, 0xd3, 0x01, 0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88}
	smbNDR32UUID    = [16]byte{0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60}
)

// Preserve shi1_type from the server. Printer/device shares are enumerable
// resources, but opening their root as a directory is not a valid access test.
type smbListedShare struct {
	Name string
	Type uint32
}

func enumerateSMBShares(pipe io.ReadWriter, host string) ([]smbListedShare, error) {
	shares := make([]smbListedShare, 0)
	// A small underlying read on a message-mode SMB pipe may return
	// STATUS_BUFFER_OVERFLOW. go-smb2's public Read discards that payload.
	// Buffer a whole maximum-sized RPC PDU before consuming its header.
	reader := bufio.NewReaderSize(pipe, 65535)
	if err := writeSMBRPC(pipe, smbRPCBind(1)); err != nil {
		return shares, fmt.Errorf("SRVSVC bind request: %w", err)
	}
	ack, err := readSMBRPCPDU(reader, 1)
	if err != nil {
		return shares, fmt.Errorf("SRVSVC bind response: %w", err)
	}
	if err := validateSMBRPCBind(ack); err != nil {
		return shares, err
	}
	seen := make(map[string]bool)
	resumes := map[uint32]bool{0: true}
	var resume uint32
	totalBytes := 0
	receivedEntries := uint64(0)
	for page := uint32(0); page < smbRPCMaxPages; page++ {
		callID := page + 2
		request, err := smbRPCEnumRequest(callID, host, resume)
		if err != nil {
			return shares, err
		}
		if err := writeSMBRPC(pipe, request); err != nil {
			return shares, fmt.Errorf("SRVSVC enumeration request: %w", err)
		}
		stub, err := readSMBRPCResponse(reader, callID)
		if err != nil {
			return shares, err
		}
		totalBytes += len(stub)
		if totalBytes > smbRPCMaxResponse {
			return shares, fmt.Errorf("SRVSVC enumeration exceeds %d bytes", smbRPCMaxResponse)
		}
		result, err := decodeSMBSharePage(stub)
		if err != nil {
			return shares, err
		}
		receivedEntries += uint64(len(result.shares))
		for _, share := range result.shares {
			// SMB share names are case-insensitive. Preserve the server's
			// first spelling and order if entries overlap across pages.
			key := strings.ToUpper(share.Name)
			if !seen[key] {
				if len(shares) >= smbRPCMaxShares {
					return shares, fmt.Errorf("SRVSVC enumeration exceeds %d shares", smbRPCMaxShares)
				}
				seen[key] = true
				shares = append(shares, share)
			}
		}
		switch result.status {
		case 0:
			// Servers report either the whole list or entries remaining at
			// this resume position. Compare with all received entries, before
			// deduplication, so overlapping pages do not imply truncation.
			if uint64(result.total) > receivedEntries {
				return shares, fmt.Errorf("SRVSVC reported %d entries but returned only %d", result.total, receivedEntries)
			}
			return shares, nil
		case smbRPCMoreData:
			if result.resume == 0 || resumes[result.resume] {
				return shares, fmt.Errorf("SRVSVC returned more data without an advancing resume handle")
			}
			if len(result.shares) == 0 {
				return shares, fmt.Errorf("SRVSVC returned more data without any entries")
			}
			resumes[result.resume] = true
			resume = result.resume
		default:
			return shares, fmt.Errorf("SRVSVC enumeration failed with Windows error %d (0x%08x)", result.status, result.status)
		}
	}
	return shares, fmt.Errorf("SRVSVC enumeration exceeds %d pages", smbRPCMaxPages)
}

func smbRPCHeader(kind byte, callID uint32, length int) []byte {
	p := make([]byte, length)
	p[0], p[2], p[3], p[4] = 5, kind, 3, 0x10
	smbRPCByteOrder.PutUint16(p[8:10], uint16(length))
	smbRPCByteOrder.PutUint32(p[12:16], callID)
	return p
}

func smbRPCBind(callID uint32) []byte {
	p := smbRPCHeader(11, callID, 72)
	smbRPCByteOrder.PutUint16(p[16:18], smbRPCFragmentSize)
	smbRPCByteOrder.PutUint16(p[18:20], smbRPCFragmentSize)
	p[24], p[30] = 1, 1 // one context, one transfer syntax
	copy(p[32:48], smbSRVSVCUUID[:])
	smbRPCByteOrder.PutUint16(p[48:50], 3)
	copy(p[52:68], smbNDR32UUID[:])
	smbRPCByteOrder.PutUint32(p[68:72], 2)
	return p
}

func smbRPCEnumRequest(callID uint32, host string, resume uint32) ([]byte, error) {
	if host == "" || strings.ContainsRune(host, 0) {
		return nil, fmt.Errorf("SRVSVC requires a nonempty server name without NUL characters")
	}
	server := utf16.Encode([]rune(`\\` + strings.TrimPrefix(host, `\\`)))
	if len(server) > 1024 {
		return nil, fmt.Errorf("SRVSVC server name is too long")
	}
	server = append(server, 0)
	// Server pointer + conformant varying string, SHARE_ENUM_STRUCT level
	// and discriminant, container pointer/empty container, preferred bytes,
	// and a non-null resume pointer (including zero on the first call).
	stub := make([]byte, 16+len(server)*2)
	smbRPCByteOrder.PutUint32(stub[0:4], 0x20000)
	smbRPCByteOrder.PutUint32(stub[4:8], uint32(len(server)))
	smbRPCByteOrder.PutUint32(stub[12:16], uint32(len(server)))
	for i, value := range server {
		smbRPCByteOrder.PutUint16(stub[16+i*2:], value)
	}
	for len(stub)%4 != 0 {
		stub = append(stub, 0)
	}
	for _, value := range []uint32{1, 1, 0x20004, 0, 0, 0xffffffff, 0x20008, resume} {
		stub = smbRPCByteOrder.AppendUint32(stub, value)
	}
	p := smbRPCHeader(0, callID, 24+len(stub))
	smbRPCByteOrder.PutUint32(p[16:20], uint32(len(stub)))
	smbRPCByteOrder.PutUint16(p[22:24], 15)
	copy(p[24:], stub)
	return p, nil
}

func writeSMBRPC(w io.Writer, p []byte) error {
	n, err := w.Write(p)
	if err != nil {
		return err
	}
	// A partial message write cannot safely be continued as a new pipe
	// message; report it instead of silently sending a truncated RPC.
	if n != len(p) {
		return io.ErrShortWrite
	}
	return nil
}

func readSMBRPCPDU(r io.Reader, callID uint32) ([]byte, error) {
	header := make([]byte, 16)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("read RPC header: %w", err)
	}
	if header[0] != 5 || header[1] != 0 || !bytes.Equal(header[4:8], []byte{0x10, 0, 0, 0}) {
		return nil, fmt.Errorf("unsupported RPC version or data representation")
	}
	if smbRPCByteOrder.Uint32(header[12:16]) != callID {
		return nil, fmt.Errorf("RPC response call ID does not match request")
	}
	if smbRPCByteOrder.Uint16(header[10:12]) != 0 {
		return nil, fmt.Errorf("unexpected RPC authentication trailer")
	}
	size := int(smbRPCByteOrder.Uint16(header[8:10]))
	if size < 16 || size > smbRPCFragmentSize {
		return nil, fmt.Errorf("invalid RPC fragment length %d", size)
	}
	p := make([]byte, size)
	copy(p, header)
	if _, err := io.ReadFull(r, p[16:]); err != nil {
		return nil, fmt.Errorf("read RPC fragment: %w", err)
	}
	return p, nil
}

func validateSMBRPCBind(p []byte) error {
	if p[2] == 13 {
		return fmt.Errorf("SRVSVC RPC bind was rejected")
	}
	// Header-signing support and concurrent multiplexing are capabilities,
	// not fragmentation bits. RPC uses the existing SMB session's security.
	if p[2] != 12 || p[3]&3 != 3 || p[3]&^byte(0x17) != 0 || len(p) < 30 {
		return fmt.Errorf("invalid SRVSVC RPC bind acknowledgement")
	}
	if smbRPCByteOrder.Uint16(p[16:18]) < 24 || smbRPCByteOrder.Uint16(p[18:20]) < 24 {
		return fmt.Errorf("SRVSVC RPC negotiated an unusable fragment size")
	}
	addrLen := int(smbRPCByteOrder.Uint16(p[24:26]))
	offset := (26 + addrLen + 3) &^ 3
	if offset+4+24 > len(p) || p[offset] != 1 {
		return fmt.Errorf("invalid SRVSVC RPC bind result list")
	}
	result := p[offset+4:]
	if smbRPCByteOrder.Uint16(result[0:2]) != 0 {
		return fmt.Errorf("SRVSVC RPC context rejected (reason %d)", smbRPCByteOrder.Uint16(result[2:4]))
	}
	if !bytes.Equal(result[4:20], smbNDR32UUID[:]) || smbRPCByteOrder.Uint32(result[20:24]) != 2 {
		return fmt.Errorf("SRVSVC RPC did not accept NDR32")
	}
	return nil
}

func readSMBRPCResponse(r io.Reader, callID uint32) ([]byte, error) {
	var stub []byte
	for fragment := 0; ; fragment++ {
		p, err := readSMBRPCPDU(r, callID)
		if err != nil {
			return nil, err
		}
		if p[2] == 3 && len(p) >= 28 {
			return nil, fmt.Errorf("SRVSVC RPC fault 0x%08x", smbRPCByteOrder.Uint32(p[24:28]))
		}
		if p[2] != 2 || len(p) < 24 {
			return nil, fmt.Errorf("invalid SRVSVC RPC response type or header")
		}
		// PENDING_CANCEL and CONC_MPX do not change the response layout.
		// DID_NOT_EXECUTE (0x20) must never become a successful enumeration.
		if (p[3]&1 != 0) != (fragment == 0) || p[3]&^byte(0x17) != 0 {
			return nil, fmt.Errorf("invalid SRVSVC RPC fragment flags")
		}
		if smbRPCByteOrder.Uint16(p[20:22]) != 0 {
			return nil, fmt.Errorf("unexpected SRVSVC RPC presentation context")
		}
		payload := p[24:]
		if len(payload) == 0 && p[3]&2 == 0 {
			return nil, fmt.Errorf("empty intermediate SRVSVC RPC fragment")
		}
		if len(stub)+len(payload) > smbRPCMaxResponse {
			return nil, fmt.Errorf("SRVSVC RPC response exceeds %d bytes", smbRPCMaxResponse)
		}
		stub = append(stub, payload...)
		if p[3]&2 != 0 {
			return stub, nil
		}
	}
}

type smbSharePage struct {
	shares []smbListedShare
	total  uint32
	resume uint32
	status uint32
}

type smbNDRReader struct {
	data []byte
	pos  int
	err  error
}

func (r *smbNDRReader) u32() uint32 {
	if r.err != nil {
		return 0
	}
	if len(r.data)-r.pos < 4 {
		r.err = fmt.Errorf("truncated SRVSVC NDR response")
		return 0
	}
	value := smbRPCByteOrder.Uint32(r.data[r.pos : r.pos+4])
	r.pos += 4
	return value
}

func (r *smbNDRReader) text() string {
	maximum, offset, count := r.u32(), r.u32(), r.u32()
	if r.err != nil {
		return ""
	}
	if offset != 0 || count == 0 || count > maximum || maximum > 65536 || uint64(count)*2 > uint64(len(r.data)-r.pos) {
		r.err = fmt.Errorf("invalid SRVSVC NDR string bounds")
		return ""
	}
	units := make([]uint16, int(count))
	for i := range units {
		units[i] = smbRPCByteOrder.Uint16(r.data[r.pos+i*2:])
	}
	r.pos += len(units) * 2
	if units[len(units)-1] != 0 {
		r.err = fmt.Errorf("unterminated SRVSVC NDR string")
		return ""
	}
	units = units[:len(units)-1]
	for i := 0; i < len(units); i++ {
		u := units[i]
		if u == 0 {
			r.err = fmt.Errorf("embedded NUL in SRVSVC NDR string")
			return ""
		}
		if u >= 0xd800 && u <= 0xdbff {
			if i+1 >= len(units) || units[i+1] < 0xdc00 || units[i+1] > 0xdfff {
				r.err = fmt.Errorf("invalid UTF-16 in SRVSVC NDR string")
				return ""
			}
			i++
		} else if u >= 0xdc00 && u <= 0xdfff {
			r.err = fmt.Errorf("invalid UTF-16 in SRVSVC NDR string")
			return ""
		}
	}
	r.pos = (r.pos + 3) &^ 3
	if r.pos > len(r.data) {
		r.err = fmt.Errorf("truncated SRVSVC NDR string padding")
		return ""
	}
	return string(utf16.Decode(units))
}

func decodeSMBSharePage(stub []byte) (smbSharePage, error) {
	var result smbSharePage
	r := smbNDRReader{data: stub}
	level, discriminant, container := r.u32(), r.u32(), r.u32()
	if r.err != nil {
		return result, r.err
	}
	if level != 1 || discriminant != 1 {
		return result, fmt.Errorf("unexpected SRVSVC enumeration level")
	}
	if container != 0 {
		entries, array := r.u32(), r.u32()
		if r.err != nil {
			return result, r.err
		}
		if entries > smbRPCMaxShares {
			return result, fmt.Errorf("SRVSVC page exceeds %d shares", smbRPCMaxShares)
		}
		if array == 0 && entries != 0 {
			return result, fmt.Errorf("SRVSVC share array is missing")
		}
		if array != 0 {
			count := r.u32()
			if r.err != nil {
				return result, r.err
			}
			if count != entries || uint64(count)*12 > uint64(len(stub)-r.pos) {
				return result, fmt.Errorf("invalid SRVSVC share array bounds")
			}
			type pointers struct{ name, shareType, remark uint32 }
			refs := make([]pointers, int(count))
			for i := range refs {
				refs[i].name = r.u32()
				refs[i].shareType = r.u32()
				refs[i].remark = r.u32()
			}
			for _, ref := range refs {
				if ref.name == 0 {
					return result, fmt.Errorf("SRVSVC returned a share without a name")
				}
				name := r.text()
				if ref.remark != 0 {
					_ = r.text()
				}
				if r.err != nil {
					return result, r.err
				}
				if name == "" {
					return result, fmt.Errorf("SRVSVC returned an empty share name")
				}
				result.shares = append(result.shares, smbListedShare{Name: name, Type: ref.shareType})
			}
		}
	}
	result.total = r.u32()
	if r.u32() != 0 {
		result.resume = r.u32()
	}
	result.status = r.u32()
	if r.err != nil {
		return result, r.err
	}
	if r.pos != len(stub) {
		return result, fmt.Errorf("unexpected trailing SRVSVC NDR data")
	}
	return result, nil
}
