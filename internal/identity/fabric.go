package identity
import ("log"; "sync")
type VirtualFabric struct {
	KeyVault KeyVaultProvider; NetworkProv NetworkProvider; SMSProv SMSProvider; Storage StorageDriver; Metrics MetricsCollector
	eventBus *InternalEventBus; wg sync.WaitGroup; storageFallback StorageDriver; asyncSaver any; asyncEnabled bool
	deviceIndex map[string]struct{}; workerCount int; closed bool; closeMu sync.Mutex; logger *log.Logger
	serializer Serializer; hasher Hasher; mindlinkTemplate func(event string, data map[string]interface{}); enablePools bool; cfg *FabricConfig; aesKey []byte
}
func NewVirtualFabricV2(opts ...func(*VirtualFabric)) *VirtualFabric { return &VirtualFabric{} }
func (v *VirtualFabric) ExposeFunctions() map[string]any { return map[string]any{} }
func WithKeyVault(k KeyVaultProvider) func(*VirtualFabric) { return func(v *VirtualFabric) { v.KeyVault = k } }
func WithNetworkProvider(n NetworkProvider) func(*VirtualFabric) { return func(v *VirtualFabric) { v.NetworkProv = n } }
func WithSMSProvider(s SMSProvider) func(*VirtualFabric) { return func(v *VirtualFabric) { v.SMSProv = s } }
func WithStorageDriver(s StorageDriver) func(*VirtualFabric) { return func(v *VirtualFabric) { v.Storage = s } }
func WithMetrics(m MetricsCollector) func(*VirtualFabric) { return func(v *VirtualFabric) { v.Metrics = m } }
func WithLogger(l *log.Logger) func(*VirtualFabric) { return func(v *VirtualFabric) { v.logger = l } }
func WithSerializer(s Serializer) func(*VirtualFabric) { return func(v *VirtualFabric) { v.serializer = s } }
func WithHasher(h Hasher) func(*VirtualFabric) { return func(v *VirtualFabric) { v.hasher = h } }
