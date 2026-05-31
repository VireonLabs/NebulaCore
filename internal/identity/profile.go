package identity
import ("context"; "sync"; "time")
type VirtualDeviceProfile struct {
	DeviceID string; Identity DeviceIdentity; Fingerprint DigitalFingerprint; KeyPair *KeyPair; Mailbox *Mailbox; SMSBox *SMSBox; Attestation *AttestationResult
	Network NetworkProfile; LinkedAccount *ExternalAccount; ActiveSession *DeviceSession; Phone *PhoneNumberBinding; Certificate *DeviceCertificate; PlayServices *PlayServicesProfile
	CreatedAt, LastActive time.Time; Meta map[string]interface{}; Memory *DeviceMemory; InputChan chan DeviceInput; State DeviceState
	isDeviceAttested bool; lastAttestation time.Time; MindLink func(event string, data map[string]interface{}); eventBus *InternalEventBus; cancelCtx context.CancelFunc; mu sync.RWMutex
}
type DeviceMemory struct { mu sync.RWMutex; store map[string]interface{}; limit int }
func NewDeviceMemory(limit int) *DeviceMemory { return &DeviceMemory{store: make(map[string]interface{}), limit: limit} }
func (dm *DeviceMemory) Record(key string, value interface{}) { dm.mu.Lock(); dm.store[key] = value; dm.mu.Unlock() }
func (dm *DeviceMemory) Read(key string) (interface{}, bool) { dm.mu.RLock(); v, ok := dm.store[key]; dm.mu.RUnlock(); return v, ok }
