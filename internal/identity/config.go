package identity
import "time"
type FabricConfig struct {
	EmulatorImage, ProxyImage, EmulatorCtxDir, ProxyCtxDir, APIListenAddr, APIToken, APKDefaultPath, AESKeyHex string
	ContainerTTL, CleanupInterval time.Duration
	UseFDroid bool
	FDroidAPKURL, InternalAppRepoDir, EmulatorDockerfile, EmulatorEntrypoint string
	ShouldAutoBuildImage bool
}
func loadConfigFromEnv() *FabricConfig { return &FabricConfig{} }
