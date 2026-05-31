package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Aurionex/NebulaCore/internal/bootstrap"
	"github.com/Aurionex/NebulaCore/internal/cryptoengine"
	"github.com/Aurionex/NebulaCore/internal/ebpf"
	"github.com/Aurionex/NebulaCore/internal/execwatcher"
	"github.com/Aurionex/NebulaCore/internal/logging"
	"github.com/Aurionex/NebulaCore/internal/monitoring"
	"github.com/Aurionex/NebulaCore/internal/secstore"
	"github.com/Aurionex/NebulaCore/internal/security"
)

func main() {
	var masterKeyFile string
	var useVault bool
	var devMode bool
	flag.StringVar(&masterKeyFile, "masterkeyfile", "", "path to master key file (hex) - required in non-dev if not using Vault")
	flag.BoolVar(&useVault, "use-vault", true, "use Vault (or configured KMS) for masterKey and secrets")
	flag.BoolVar(&devMode, "dev-mode", false, "enable developer mode (allows LocalSigner, relaxed checks)")
	flag.Parse()

	// Export DEV_MODE env for components that consult it (API middleware etc.)
	if devMode {
		_ = os.Setenv("DEV_MODE", "1")
	} else {
		_ = os.Setenv("DEV_MODE", "0")
	}

	// If not dev-mode, require KMS or masterKey file based on useVault flag.
	var kms secstore.KMSWrapper
	if !devMode {
		// Prefer KMS (Vault Transit / PKCS#11) via bootstrap helper.
		if useVault {
			// Bootstrap will fatal if it cannot provide an appropriate KMS in non-dev.
			k, err := bootstrap.Bootstrap()
			if err != nil {
				log.Fatalf("failed to initialize KMS (bootstrap): %v", err)
			}
			if k == nil {
				log.Fatalf("bootstrap returned nil KMS in non-dev; refusing to start without KMS")
			}
			kms = k
			log.Println("[bootstrap] KMS initialized")
		} else {
			// useVault == false -> require masterKeyFile provided
			if masterKeyFile == "" {
				log.Fatalf("non-dev mode without Vault requires --masterkeyfile")
			}
		}
	}

	// Load masterKey if provided (hex-encoded). Zero memory after use where possible.
	var masterKey []byte
	if masterKeyFile != "" {
		b, err := os.ReadFile(masterKeyFile)
		if err != nil {
			log.Fatalf("failed to read masterKeyFile: %v", err)
		}
		s := string(b)
		s = string([]byte(s)) // normalize
		s = TrimSpaceNewline(s)
		mk, err := hex.DecodeString(s)
		if err != nil {
			log.Fatalf("masterKey file decode error (expect hex): %v", err)
		}
		if len(mk) != 32 {
			log.Fatalf("masterKey must be 32 bytes (decoded); got %d bytes", len(mk))
		}
		masterKey = make([]byte, len(mk))
		copy(masterKey, mk)
		// zero mk slice
		for i := range mk {
			mk[i] = 0
		}
	}

	// Initialize keystore, prefer KMS-wrapped mode. NewSimpleEncryptedStore requires masterKey (if not using KMS).
	ks, err := secstore.NewSimpleEncryptedStore("/var/lib/laserwall/keystore", masterKey)
	// Zero local masterKey variable now (keystore copied it securely)
	if masterKey != nil {
		for i := range masterKey {
			masterKey[i] = 0
		}
		masterKey = nil
	}
	if err != nil {
		log.Fatalf("keystore init: %v", err)
	}
	// If we got KMS from bootstrap, attach it to keystore
	if kms != nil {
		ks.SetKMS(kms)
	}

	// Create a KMS-backed signer wrapper if not dev-mode
	var kmsSignFunc func(ctx context.Context, data []byte) ([]byte, error)
	if !devMode {
		if kms == nil {
			// If we have no KMS in non-dev: fatal (defense-in-depth)
			log.Fatalf("no KMS configured in non-dev mode; refusing to start")
		}
		// choose the signing key name to use in KMS (configurable via env)
		signKey := os.Getenv("EBPF_SIGNER_KEY")
		if signKey == "" {
			// sensible default
			signKey = "ebpf-sign-key"
		}
		// kmsSignFunc uses KMS wrapper's Sign method with timeout
		kmsSignFunc = func(ctx context.Context, data []byte) ([]byte, error) {
			// ensure bounded timeout
			ctx2, cancel := context.WithTimeout(ctx, 8*time.Second)
			defer cancel()
			return kms.Sign(ctx2, signKey, data)
		}
	}

	// Create Auditor: enforceSigned = !devMode (production forces signed audit)
	enforceSignedAudit := !devMode
	aud := logging.NewAuditor(ks, "audit_signer", kmsSignFunc, enforceSignedAudit)

	// Create other components
	ebpfSigner := (func() ebpf.Signer {
		if devMode {
			log.Println("[startup] dev-mode enabled: using LocalSigner (INSECURE) for eBPF signing")
			return &ebpf.LocalSigner{}
		}
		// production: use KMS-backed signer wrapper
		if kms == nil {
			// we already fatal'd above when no KMS in non-dev; defensive check
			log.Fatalf("no KMS available for production signer")
		}
		// construct a wrapper that implements ebpf.Signer using kms.Sign
		return &KMSSigner{KMS: kms, KeyName: os.Getenv("EBPF_SIGNER_KEY")}
	})()

	ebpfL := ebpf.NewLoader("/opt/laserwall/ebpf", "", ebpfSigner, log.Default())

	reg := cryptoengine.NewRegistry()
	att := security.NewTPMAttestor(ks)
	cosign := security.NewInternalCosignVerifier(ks)
	enf := security.NewEnforcementManagerWithDeps(ks, aud, cosign, att, nil)
	fw := security.NewLaserFirewall()

	// Fanotify watcher: only initialize if running as root (or admin allowed)
	var watcher *execwatcher.FanotifyWatcher
	if os.Geteuid() == 0 {
		watcher = execwatcher.NewFanotifyWatcher(enf, "/opt/apps")
	} else {
		log.Println("[startup] not running as root: fanotify watcher will be disabled (use root or configure alternative watcher)")
		watcher = nil
	}

	mon := monitoring.NewMonitor(enf, security.NewEntropyAggregator(), aud)

	coord := bootstrap.NewCoordinator(ks, aud, enf, fw, ebpfL, watcher, mon, reg)
	if err := coord.Start(); err != nil {
		log.Fatalf("coordinator start failed: %v", err)
	}

	// wait for termination signals
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("shutdown requested")
	coord.Stop()
	// ensure auditor closed
	_ = aud.Close()
	time.Sleep(1 * time.Second)
}

// TrimSpaceNewline trims spaces and trailing newline characters
func TrimSpaceNewline(s string) string {
	// remove BOMs and common newline chars
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r' || s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	return s
}

// KMSSigner adapts secstore.KMSWrapper Sign to ebpf.Signer
type KMSSigner struct {
	KMS     secstore.KMSWrapper
	KeyName string
}

func (k *KMSSigner) Sign(data []byte) ([]byte, error) {
	if k.KMS == nil {
		return nil, fmt.Errorf("kms not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if k.KeyName == "" {
		return k.KMS.Sign(ctx, "default", data)
	}
	return k.KMS.Sign(ctx, k.KeyName, data)
}