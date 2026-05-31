package identity
import ("sync"; "time")
type Event struct { DeviceID, Action string; Payload map[string]interface{}; Priority int; Timestamp time.Time }
type InternalEventBus struct { high, normal, low chan Event; closed bool; mu sync.Mutex }
func NewInternalEventBus(buffer int) *InternalEventBus { return &InternalEventBus{} }
func (eb *InternalEventBus) Publish(event Event) {}
func (eb *InternalEventBus) Close() {}
func (eb *InternalEventBus) StartWorkers(n int, wg *sync.WaitGroup, deviceMap func(id string) (*VirtualDeviceProfile, bool)) {}
