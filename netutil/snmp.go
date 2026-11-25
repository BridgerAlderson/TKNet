package netutil

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
)

// GetSNMPInfo queries the target IP for basic SNMP sysDescr (1.3.6.1.2.1.1.1.0) and sysName (1.3.6.1.2.1.1.5.0)
func GetSNMPInfo(ip string, community string, timeoutSec int) (string, error) {
	return GetSNMPInfoContext(context.Background(), ip, community, timeoutSec)
}

func GetSNMPInfoContext(ctx context.Context, ip string, community string, timeoutSec int) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if timeoutSec < 1 || timeoutSec > 60 {
		return "", fmt.Errorf("SNMP timeout must be between 1 and 60 seconds")
	}
	if community == "" {
		community = "public"
	}

	params := &gosnmp.GoSNMP{
		Context:   ctx,
		Target:    ip,
		Port:      161,
		Community: community,
		Version:   gosnmp.Version2c,
		Timeout:   time.Duration(timeoutSec) * time.Second,
		Retries:   1,
	}

	err := params.Connect()
	if err != nil {
		return "", fmt.Errorf("SNMP connect err: %w", err)
	}
	defer params.Conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = params.Conn.Close() })
	defer stop()

	oids := []string{"1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.5.0"} // sysDescr, sysName
	result, err := params.Get(oids)
	if err != nil {
		return "", fmt.Errorf("SNMP get err: %w", err)
	}
	return snmpResponseInfo(result)
}

func snmpResponseInfo(result *gosnmp.SnmpPacket) (string, error) {
	if result == nil {
		return "", fmt.Errorf("empty SNMP response")
	}
	if result.Error != gosnmp.NoError {
		return "", fmt.Errorf("SNMP response error: %s (index %d)", result.Error, result.ErrorIndex)
	}
	return formatSNMPInfo(result.Variables)
}

func formatSNMPInfo(variables []gosnmp.SnmpPDU) (string, error) {
	var sysDescr, sysName string

	for _, variable := range variables {
		switch strings.TrimPrefix(variable.Name, ".") {
		case "1.3.6.1.2.1.1.1.0":
			if val, ok := variable.Value.([]byte); ok {
				sysDescr = string(val)
			}
		case "1.3.6.1.2.1.1.5.0":
			if val, ok := variable.Value.([]byte); ok {
				sysName = string(val)
			}
		}
	}

	if sysDescr != "" {
		info := sysDescr
		if sysName != "" {
			info = fmt.Sprintf("[%s] %s", sysName, sysDescr)
		}
		// Clean up newlines for cleaner output
		info = strings.ReplaceAll(info, "\r\n", " ")
		info = strings.ReplaceAll(info, "\n", " ")
		return info, nil
	}

	return "", fmt.Errorf("no SNMP data found")
}
