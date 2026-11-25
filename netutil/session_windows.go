//go:build windows

package netutil

import "os/exec"

// The file manager owns authentication. Never expose credentials in process
// arguments or remove existing user sessions to open a share.
func OpenShareInExplorer(sharePath, domain, username, password string, useHash bool) error {
	_, location, err := shareLocations(sharePath)
	if err != nil {
		return err
	}
	cmd := exec.Command("explorer.exe", location)
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}
