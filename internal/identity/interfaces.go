package identity
import "crypto/ed25519"
type KeyVaultProvider interface {
	GenerateKey(deviceID string) (ed25519.PublicKey, ed25519.PrivateKey, error)
	Sign(deviceID string, msg []byte) ([]byte, error)
	Verify(pub ed25519.PublicKey, msg, sig []byte) bool
}
type NetworkProvider interface {
	AllocateIdentity(deviceID string) (DeviceIdentity, error)
	DescribeNetwork(deviceID string) (NetworkProfile, error)
}
type SMSProvider interface {
	RegisterNumber(number string, deviceID string) error
	DeliverSMS(number string, from string, body string) error
}
type StorageDriver interface {
	SaveDevice(device *VirtualDeviceProfile) error
	LoadDevice(deviceID string) (*VirtualDeviceProfile, error)
	DeleteDevice(deviceID string) error
	ListDevices() ([]*VirtualDeviceProfile, error)
}
type MetricsCollector interface { Emit(event string, fields map[string]interface{}) }
type Serializer interface { Marshal(v interface{}) ([]byte, error); Unmarshal(data []byte, v interface{}) error }
type Hasher interface { Sum8(data []byte) []byte }
