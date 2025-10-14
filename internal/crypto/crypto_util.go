package crypto_util

import (
	"crypto/rand"
	"io"
	"log"
)

// RandReader يعيد مصدر عشوائي آمن لجميع العمليات التشفيرية
func RandReader() io.Reader {
	return rand.Reader
}

// GenerateNonce يولد Nonce آمن للحفاظ على التشفير السليم
func GenerateNonce(size int) ([]byte, error) {
	nonce := make([]byte, size)
	_, err := io.ReadFull(RandReader(), nonce)
	if err != nil {
		log.Printf("[Crypto] Failed to generate nonce: %v", err)
		return nil, err
	}
	return nonce, nil
}

// Usage example:
// nonce, err := crypto_util.GenerateNonce(12)
// if err != nil { return err }
// الآن يمكن استخدام nonce في AES-GCM أو أي تشفير آخر