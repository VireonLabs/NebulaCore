package bootstrap

import (
	"log"
	"os"
	"time"

	"konrotaharai-netizen/internal/secstore"
)

// DetectEnv يكتشف تلقائياً متغيرات البيئة الأساسية
// Returns configured vault address and PKCS#11 library path (if any)
func DetectEnv() (vaultAddr string, pkcs11Lib string) {
	vaultAddr = os.Getenv("VAULT_ADDR")
	pkcs11Lib = os.Getenv("PKCS11_LIB")

	if vaultAddr == "" {
		log.Fatal("[Bootstrap] VAULT_ADDR not set. Aborting.")
	}

	if pkcs11Lib == "" {
		log.Println("[Bootstrap] PKCS11_LIB not set, defaulting to software HSM path")
		pkcs11Lib = "/usr/local/lib/softhsm/libsofthsm2.so"
	} else {
		log.Printf("[Bootstrap] PKCS11_LIB detected: %s\n", pkcs11Lib)
	}

	log.Printf("[Bootstrap] Using VAULT_ADDR: %s\n", vaultAddr)
	return
}

// InitKMS يقوم بتهيئة KMS المناسب تلقائياً (Vault أو PKCS#11)
// Returns secstore.KMSWrapper suitable for keystore wiring.
func InitKMS() (secstore.KMSWrapper, error) {
	vaultAddr, pkcs11Lib := DetectEnv()

	// Prefer Vault transit if VAULT_ADDR exists (common production setup)
	// Try to create a VaultTransitKMS adapter first
	if vaultAddr != "" {
		if vk, err := secstore.NewVaultTransitKMSFromEnv("laserwall-transit"); err == nil {
			log.Println("[Bootstrap] Vault Transit KMS initialized successfully")
			return vk, nil
		} else {
			log.Printf("[Bootstrap] Vault Transit init failed (will try PKCS11 if available): %v", err)
		}
	}

	// Fallback / alternative: PKCS#11 provider (SoftHSM or hardware HSM)
	if pkcs11Lib != "" {
		// Use reasonable defaults; optional env vars may override token label / pin / key labels
		pin := os.Getenv("PKCS11_PIN")
		tokenLabel := os.Getenv("PKCS11_TOKEN_LABEL")
		aesLabel := os.Getenv("PKCS11_AES_LABEL")
		signLabel := os.Getenv("PKCS11_SIGN_LABEL")
		adapter, err := secstore.NewPKCS11KMSAdapter(pkcs11Lib, tokenLabel, pin, aesLabel, signLabel)
		if err != nil {
			log.Fatalf("[Bootstrap] Failed to initialize PKCS11 provider: %v", err)
			return nil, err
		}
		log.Println("[Bootstrap] PKCS11 provider initialized successfully")
		return adapter, nil
	}

	return nil, nil
}

// Bootstrap convenience for auto-bootstrap of KMS; logs fatal on irrecoverable errors.
func Bootstrap() secstore.KMSWrapper {
	kmsInstance, err := InitKMS()
	if err != nil {
		log.Fatalf("[Bootstrap] Bootstrap failed: %v", err)
	}
	return kmsInstance
}