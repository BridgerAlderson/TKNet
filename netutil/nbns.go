package netutil

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

var ErrNoResponse = errors.New("no response")

func NBNSQuery(ip net.IP, timeout time.Duration) (string, error) {
	return NBNSQueryContext(context.Background(), ip, timeout)
}

// A connected UDP socket restricts replies to the requested IP and port. A new
// transaction ID and strict NBSTAT validation reject unrelated/stale datagrams.
// A valid response without a workstation name returns an empty name and nil.
func NBNSQueryContext(ctx context.Context, ip net.IP, timeout time.Duration) (string, error) {
	if ip.To4() == nil || timeout <= 0 {
		return "", fmt.Errorf("NetBIOS requires IPv4 and a positive timeout")
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "udp4", net.JoinHostPort(ip.String(), "137"))
	if err != nil {
		return "", err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return "", err
	}
	var idBytes [2]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		return "", err
	}
	id := binary.BigEndian.Uint16(idBytes[:])
	if _, err := conn.Write(buildNBSTATPacket(id)); err != nil {
		return "", err
	}
	buf := make([]byte, 65535)
	var invalid error
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if invalid != nil {
				return "", invalid
			}
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			if IsLocalProbeError(err) {
				return "", err
			}
			return "", ErrNoResponse
		}
		name, err := parseNBSTATResponse(buf[:n], id)
		if err == nil {
			return name, nil
		}
		invalid = fmt.Errorf("invalid node-status response: %w", err)
	}
}

func buildNBSTATPacket(id uint16) []byte {
	packet := make([]byte, 50)
	binary.BigEndian.PutUint16(packet[0:2], id)
	binary.BigEndian.PutUint16(packet[4:6], 1)
	packet[12] = 32
	name := [16]byte{'*'}
	for i, b := range name {
		packet[13+i*2] = (b >> 4) + 'A'
		packet[14+i*2] = (b & 15) + 'A'
	}
	binary.BigEndian.PutUint16(packet[46:48], 0x21)
	binary.BigEndian.PutUint16(packet[48:50], 1)
	return packet
}

// skipNBName handles full names and compression pointers, rejecting truncated
// labels, pointer loops, forward/header pointers and invalid first-level names.
func skipNBName(data []byte, offset int) (int, error) {
	next, labels, size := -1, 0, 0
	for hops := 0; hops < 128; hops++ {
		if offset < 12 || offset >= len(data) {
			break
		}
		length := int(data[offset])
		if length&0xc0 == 0xc0 {
			if offset+1 >= len(data) {
				break
			}
			pointer := (length&0x3f)<<8 | int(data[offset+1])
			if pointer < 12 || pointer >= offset {
				break
			}
			if next < 0 {
				next = offset + 2
			}
			offset = pointer
			continue
		}
		if length > 63 || offset+1+length > len(data) {
			break
		}
		if length == 0 {
			if labels == 0 {
				break
			}
			if next < 0 {
				next = offset + 1
			}
			return next, nil
		}
		if labels == 0 {
			if length != 32 {
				break
			}
			for _, b := range data[offset+1 : offset+1+length] {
				if b < 'A' || b > 'P' {
					return 0, fmt.Errorf("invalid NetBIOS name encoding")
				}
			}
		}
		size += length + 1
		if size > 254 {
			break
		}
		labels++
		offset += length + 1
	}
	return 0, fmt.Errorf("invalid or truncated NetBIOS name")
}

// RFC 1002 §4.2.18: header, NBSTAT/IN record, declared RDATA length, all name
// entries and the 46-byte statistics block must be present before accepting it.
func parseNBSTATResponse(data []byte, expectedID uint16) (string, error) {
	if len(data) < 12 {
		return "", fmt.Errorf("short header")
	}
	if binary.BigEndian.Uint16(data[:2]) != expectedID {
		return "", fmt.Errorf("transaction mismatch")
	}
	flags := binary.BigEndian.Uint16(data[2:4])
	if flags&0xfa0f != 0x8000 {
		return "", fmt.Errorf("not a successful complete query response")
	}
	questions := binary.BigEndian.Uint16(data[4:6])
	if questions > 1 || binary.BigEndian.Uint16(data[6:8]) != 1 ||
		binary.BigEndian.Uint16(data[8:10]) != 0 || binary.BigEndian.Uint16(data[10:12]) != 0 {
		return "", fmt.Errorf("invalid section counts")
	}
	offset := 12
	var err error
	if questions == 1 {
		offset, err = skipNBName(data, offset)
		if err != nil {
			return "", err
		}
		if offset+4 > len(data) || binary.BigEndian.Uint16(data[offset:offset+2]) != 0x21 || binary.BigEndian.Uint16(data[offset+2:offset+4]) != 1 {
			return "", fmt.Errorf("invalid question")
		}
		offset += 4
	}
	offset, err = skipNBName(data, offset)
	if err != nil {
		return "", err
	}
	if offset+10 > len(data) {
		return "", fmt.Errorf("truncated resource header")
	}
	if binary.BigEndian.Uint16(data[offset:offset+2]) != 0x21 || binary.BigEndian.Uint16(data[offset+2:offset+4]) != 1 {
		return "", fmt.Errorf("not an NBSTAT/IN answer")
	}
	length := int(binary.BigEndian.Uint16(data[offset+8 : offset+10]))
	offset += 10
	if length < 47 || offset+length != len(data) {
		return "", fmt.Errorf("invalid RDATA length")
	}
	count := int(data[offset])
	if length != 1+count*18+46 {
		return "", fmt.Errorf("incomplete name table or statistics")
	}
	offset++
	workstation, server := "", ""
	for i := 0; i < count; i++ {
		entry := data[offset : offset+18]
		offset += 18
		nameFlags := binary.BigEndian.Uint16(entry[16:18])
		if nameFlags&0x8000 != 0 || nameFlags&0x1800 != 0 || nameFlags&0x0400 == 0 {
			continue
		}
		name := strings.TrimRight(string(entry[:15]), " \x00")
		valid := name != ""
		for _, b := range []byte(name) {
			if b < 32 || b == 127 {
				valid = false
			}
		}
		if !valid {
			continue
		}
		if entry[15] == 0 && workstation == "" {
			workstation = name
		}
		if entry[15] == 0x20 && server == "" {
			server = name
		}
	}
	if workstation != "" {
		return workstation, nil
	}
	return server, nil
}
