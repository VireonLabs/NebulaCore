package agent

import "errors"

var (
	errInvalidNicConfig                 = errors.New("NIC config wasn't of the form DEVICE/MACADDR")
	errInvalidDriveSpecificationNoSuffix = errors.New("invalid drive specification. Must have :rw or :ro suffix")
	errInvalidDriveSpecificationNoPath  = errors.New("invalid drive specification. Must have path")
	errUnableToParseVsockDevices        = errors.New("unable to parse vsock devices")
	errUnableToParseVsockCID            = errors.New("unable to parse vsock CID as a number")
	errConflictingLogOpts               = errors.New("vmm-log-fifo and firecracker-log cannot be used together")
	errUnableToCreateFifoLogFile        = errors.New("failed to create fifo log file")
	errInvalidMetadata                  = errors.New("invalid metadata, unable to parse as json")
)