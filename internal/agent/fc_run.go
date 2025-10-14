package agent

import (
	"context"
	"os"
	"os/exec"
)

// Wrapper for running Firecracker microVM using fc-run helper
func RunFirecracker(ctx context.Context, kernel string, rootfs string, cmdline []string, env map[string]string) (int, string, error) {
	args := []string{kernel, rootfs}
	args = append(args, cmdline...)
	cmd := exec.CommandContext(ctx, "fc-run", args...)

	// Set environment
	if env != nil {
		environ := os.Environ()
		for k, v := range env {
			environ = append(environ, k+"="+v)
		}
		cmd.Env = environ
	}

	out, err := cmd.CombinedOutput()
	logs := string(out)
	if err != nil {
		return 1, logs, err
	}
	return 0, logs, nil
}