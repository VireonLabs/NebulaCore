package identity
import ("time"; "math/rand")
var mathrand = rand.New(rand.NewSource(time.Now().UnixNano()))
func NewPooledIdentity() *DeviceIdentity { return &DeviceIdentity{} }
func PutPooledIdentity(d *DeviceIdentity) {}
