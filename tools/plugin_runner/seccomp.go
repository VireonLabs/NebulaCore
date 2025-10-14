package main

import (
	"encoding/json"
	"fmt"
	"os"
	"syscall"

	scmp "github.com/seccomp/libseccomp-golang"
)

// applySeccompProfile loads a JSON profile (simple schema) and installs a seccomp filter using libseccomp-golang.
// The JSON format is expected to contain "syscalls": [ {"names":[...], "action":"SCMP_ACT_ALLOW" }, ... ]
func applySeccompProfile(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var profile map[string]interface{}
	if err := json.Unmarshal(b, &profile); err != nil {
		return err
	}
	// collect syscall names
	names := []string{}
	if s, ok := profile["syscalls"].([]interface{}); ok {
		for _, it := range s {
			if m, ok := it.(map[string]interface{}); ok {
				if ns, ok := m["names"].([]interface{}); ok {
					for _, n := range ns {
						if sname, ok := n.(string); ok {
							names = append(names, sname)
						}
					}
				}
			}
		}
	}
	// Create filter with default action ERRNO(EPERM)
	filter, err := scmp.NewFilter(scmp.ActErrno.SetReturnCode(int16(syscall.EPERM)))
	if err != nil {
		return fmt.Errorf("seccomp new filter: %w", err)
	}
	for _, sname := range names {
		call, err := scmp.GetSyscallFromName(sname)
		if err != nil {
			// ignore unknown syscall on platform
			continue
		}
		if err := filter.AddRule(call, scmp.ActAllow); err != nil {
			// continue on error
			continue
		}
	}
	if err := filter.Load(); err != nil {
		return fmt.Errorf("seccomp load: %w", err)
	}
	return nil
}