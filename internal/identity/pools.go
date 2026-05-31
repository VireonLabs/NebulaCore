package identity
import "sync"
var ( DevicePool, IdentityPool, MailPool, SMSPool *sync.Pool )
func init() {
	DevicePool = &sync.Pool{New: func() interface{} { return &VirtualDeviceProfile{} }}
	IdentityPool = &sync.Pool{New: func() interface{} { return &DeviceIdentity{} }}
	MailPool = &sync.Pool{New: func() interface{} { return &Mail{} }}
	SMSPool = &sync.Pool{New: func() interface{} { return &SMS{} }}
}
