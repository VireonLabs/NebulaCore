package agent

import (
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	firecracker "github.com/firecracker-microvm/firecracker-go-sdk"
	models "github.com/firecracker-microvm/firecracker-go-sdk/client/models"
)

func newOptions() *options {
	return &options{
		createFifoFileLogs: createFifoFileLogs,
	}
}

type options struct {
	FcBinary           string
	FcKernelImage      string
	FcKernelCmdLine    string
	FcInitrd           string
	FcRootDrivePath    string
	FcRootPartUUID     string
	FcAdditionalDrives []string
	FcNicConfig        []string
	FcVsockDevices     []string
	FcLogFifo          string
	FcLogLevel         string
	FcMetricsFifo      string
	FcDisableSmt       bool
	FcCPUCount         int64
	FcCPUTemplate      string
	FcMemSz            int64
	FcMetadata         string
	FcFifoLogFile      string
	FcSocketPath       string
	Debug              bool
	Version            bool

	Id           string
	ExecFile     string
	JailerBinary string

	Uid      int
	Gid      int
	NumaNode int

	ChrootBaseDir string
	Daemonize     bool

	closers       []func() error
	validMetadata interface{}

	createFifoFileLogs func(fifoPath string) (*os.File, error)
}

// Converts options to a usable firecracker config
func (opts *options) getFirecrackerConfig() (firecracker.Config, error) {
	// validate metadata json
	if opts.FcMetadata != "" {
		if err := json.Unmarshal([]byte(opts.FcMetadata), &opts.validMetadata); err != nil {
			return firecracker.Config{}, fmt.Errorf("%s: %v", errInvalidMetadata.Error(), err)
		}
	}
	//setup NICs
	NICs, err := opts.getNetwork()
	if err != nil {
		return firecracker.Config{}, err
	}
	// BlockDevices
	blockDevices, err := opts.getBlockDevices()
	if err != nil {
		return firecracker.Config{}, err
	}

	// vsocks
	vsocks, err := parseVsocks(opts.FcVsockDevices)
	if err != nil {
		return firecracker.Config{}, err
	}

	//fifos
	fifo, err := opts.handleFifos()
	if err != nil {
		return firecracker.Config{}, err
	}

	var (
		socketPath string
		jail       *firecracker.JailerConfig
	)

	if opts.JailerBinary != "" {
		jail = &firecracker.JailerConfig{
			GID:            firecracker.Int(opts.Gid),
			UID:            firecracker.Int(opts.Uid),
			ID:             opts.Id,
			NumaNode:       firecracker.Int(opts.NumaNode),
			ExecFile:       opts.ExecFile,
			JailerBinary:   opts.JailerBinary,
			ChrootBaseDir:  opts.ChrootBaseDir,
			Daemonize:      opts.Daemonize,
			ChrootStrategy: firecracker.NewNaiveChrootStrategy(opts.FcKernelImage),
			Stdout:         os.Stdout,
			Stderr:         os.Stderr,
			Stdin:          os.Stdin,
		}
	} else {
		if opts.FcSocketPath != "" {
			socketPath = opts.FcSocketPath
		} else {
			socketPath = getSocketPath()
		}
	}

	return firecracker.Config{
		SocketPath:        socketPath,
		LogFifo:           opts.FcLogFifo,
		LogLevel:          opts.FcLogLevel,
		MetricsFifo:       opts.FcMetricsFifo,
		FifoLogWriter:     fifo,
		KernelImagePath:   opts.FcKernelImage,
		KernelArgs:        opts.FcKernelCmdLine,
		InitrdPath:        opts.FcInitrd,
		Drives:            blockDevices,
		NetworkInterfaces: NICs,
		VsockDevices:      vsocks,
		MachineCfg: models.MachineConfiguration{
			VcpuCount:   firecracker.Int64(opts.FcCPUCount),
			CPUTemplate: models.CPUTemplate(opts.FcCPUTemplate),
			Smt:         firecracker.Bool(!opts.FcDisableSmt),
			MemSizeMib:  firecracker.Int64(opts.FcMemSz),
		},
		JailerCfg: jail,
		VMID:      opts.Id,
	}, nil
}

// ... باقي الدوال كما في النسخة الأصلية (parseDevice, parseBlockDevices, etc)