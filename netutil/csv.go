package netutil

import "strings"

// SpreadsheetText prevents untrusted metadata being interpreted as a formula.
// CSV quoting is applied separately by encoding/csv.
func SpreadsheetText(value string) string {
	significant := strings.TrimSpace(value)
	if (len(significant) > 0 && strings.ContainsRune("=+-@", rune(significant[0]))) ||
		(len(value) > 0 && strings.ContainsRune("\t\r\n", rune(value[0]))) {
		return "'" + value
	}
	return value
}
