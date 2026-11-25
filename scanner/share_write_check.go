package scanner

import (
	"fmt"
	"io"
	"os"
)

// A write check may create only a new file. Report cleanup failures separately
// from access rights so operators can remove any test file that remains.
func checkShareWrite(name string, open func(string, int, os.FileMode) (io.Closer, error), remove func(string) error) (bool, []string) {
	writable, warnings, _ := checkShareWriteDetailed(name, open, remove)
	return writable, warnings
}

func checkShareWriteDetailed(name string, open func(string, int, os.FileMode) (io.Closer, error), remove func(string) error) (bool, []string, error) {
	file, err := open(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return false, nil, err
	}
	var warnings []string
	if err := file.Close(); err != nil {
		warnings = append(warnings, fmt.Sprintf("closing temporary file %s failed: %v", name, err))
	}
	if err := remove(name); err != nil {
		warnings = append(warnings, fmt.Sprintf("remove temporary file %s manually; cleanup failed: %v", name, err))
	}
	return true, warnings, nil
}
