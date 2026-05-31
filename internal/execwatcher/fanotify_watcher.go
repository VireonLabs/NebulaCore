package execwatcher

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/Aurionex/NebulaCore/internal/security"

	"golang.org/x/sys/unix"
)

// FanotifyWatcher monitors executions using fanotify API and delegates to EnforcementManager.
type FanotifyWatcher struct {
	enf       *security.EnforcementManager
	fd        int
	ctx       context.Context
	cancel    context.CancelFunc
	watchPath string
}

// NewFanotifyWatcher constructs watcher with explicit watchPath.
func NewFanotifyWatcher(enf *security.EnforcementManager, watchPath string) *FanotifyWatcher {
	if watchPath == "" {
		watchPath = "/opt/apps"
	}
	return &FanotifyWatcher{enf: enf, watchPath: watchPath}
}

func (w *FanotifyWatcher) ID() string { return "fanotify" }

func (w *FanotifyWatcher) Start() error {
	// require root for fanotify
	if os.Geteuid() != 0 {
		return fmt.Errorf("fanotify requires root privileges")
	}
	fd, err := unix.FanotifyInit(unix.FAN_CLASS_NOTIF|unix.FAN_CLOEXEC, unix.O_RDONLY|unix.O_LARGEFILE)
	if err != nil {
		return fmt.Errorf("fanotify init failed: %w", err)
	}
	w.fd = fd
	if err := unix.FanotifyMark(fd, unix.FAN_MARK_ADD|unix.FAN_MARK_MOUNT, unix.FAN_OPEN_EXEC, -1, w.watchPath); err != nil {
		unix.Close(fd)
		return fmt.Errorf("fanotify mark failed: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	w.ctx = ctx
	w.cancel = cancel
	go w.loop()
	log.Println("[fanotify] started watching", w.watchPath)
	return nil
}

func (w *FanotifyWatcher) Stop(ctx context.Context) error {
	if w.cancel != nil {
		w.cancel()
	}
	if w.fd != 0 {
		_ = unix.Close(w.fd)
		w.fd = 0
	}
	return nil
}

func (w *FanotifyWatcher) Health() map[string]interface{} {
	return map[string]interface{}{"watch": w.watchPath, "fd": w.fd}
}

func (w *FanotifyWatcher) loop() {
	file := os.NewFile(uintptr(w.fd), "fanotify")
	if file == nil {
		return
	}
	defer file.Close()
	buf := make([]byte, 4096)
	for {
		select {
		case <-w.ctx.Done():
			return
		default:
			n, err := file.Read(buf)
			if err != nil {
				if err == io.EOF {
					time.Sleep(100 * time.Millisecond)
					continue
				}
				log.Println("[fanotify] read error:", err)
				time.Sleep(time.Second)
				continue
			}
			if n <= 0 {
				continue
			}
			// Best-effort: avoid heavy /proc scanning. Inspect events by checking recently modified execs under watchPath.
			_ = w.scanRecentExecs()
		}
	}
}

// scanRecentExecs is a lightweight best-effort approach to find execs under watched path.
func (w *FanotifyWatcher) scanRecentExecs() error {
	procDir := "/proc"
	entries, _ := os.ReadDir(procDir)
	now := time.Now()
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid := e.Name()
		exePath := filepath.Join(procDir, pid, "exe")
		target, err := os.Readlink(exePath)
		if err != nil {
			continue
		}
		if len(target) >= len(w.watchPath) && target[:len(w.watchPath)] == w.watchPath {
			info, err := os.Stat(target)
			if err == nil {
				// consider only recently modified executables to limit work
				if now.Sub(info.ModTime()) < 30*time.Second {
					allowed := w.enf.EnforceExecution(context.Background(), target, 0)
					if !allowed {
						_ = quarantineBinary(target)
					}
				}
			}
		}
	}
	return nil
}

// quarantineBinary copies the binary into quarantine atomically and reduces privileges on original.
func quarantineBinary(path string) error {
	dstDir := "/var/lib/laserwall/quarantine"
	if err := os.MkdirAll(dstDir, 0o700); err != nil {
		return err
	}
	base := filepath.Base(path)
	dst := filepath.Join(dstDir, base+"."+time.Now().Format("20060102T150405"))

	in, err := os.Open(path)
	if err != nil {
		_ = os.Chmod(path, 0)
		return err
	}
	defer in.Close()

	outTmp := dst + ".tmp"
	out, err := os.OpenFile(outTmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		_ = os.Chmod(path, 0)
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		_ = os.Remove(outTmp)
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		_ = os.Remove(outTmp)
		return err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(outTmp)
		return err
	}
	if err := os.Rename(outTmp, dst); err != nil {
		_ = os.Remove(outTmp)
		return err
	}
	// reduce privileges of the original as a defensive measure
	_ = os.Chmod(path, 0o000)
	return nil
}