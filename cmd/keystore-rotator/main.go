package main

import (
	"context"
	"log"
	"os"

	"konrotaharai-netizen/internal/secstore"
)

func main() {
	dir := os.Getenv("KEYSTORE_DIR")
	if dir == "" {
		dir = "/var/lib/laserwall/keystore"
	}
	// Initialize store without local masterKey; we expect bootstrap to provide KMS or environment.
	store, err := secstore.NewSimpleEncryptedStore(dir, nil)
	if err != nil {
		log.Fatalf("new store: %v", err)
	}
	// Attempt to configure Vault KMS automatically if available
	vk, err := secstore.NewVaultTransitKMSFromEnv("laserwall-transit")
	if err == nil {
		store.SetKMS(vk)
	} else {
		log.Fatalf("no KMS available: %v", err)
	}
	log.Println("starting rewrap operation")
	if err := store.RewrapAllFiles(context.Background()); err != nil {
		log.Fatalf("rewrap failed: %v", err)
	}
	log.Println("rewrap completed")
	os.Exit(0)
}