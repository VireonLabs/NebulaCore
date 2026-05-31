package identity
import ("crypto/ed25519"; "time")
type DeviceIdentity struct { IP, ASN, Carrier, Email, SIM string }
type KeyPair struct { PublicKey ed25519.PublicKey; PrivateKey ed25519.PrivateKey }
type AttestationResult struct { DeviceID, Status, Token string; When int64 }
type NetworkProfile struct { IP, ASN, Carrier string }
type ExternalAccount struct { Kind, Address, Provider string; Meta map[string]interface{} }
type DeviceSession struct { SessionID, DeviceID string; Account *ExternalAccount; StartedAt, LastCheck, ExpireAt time.Time; IsActive bool }
type PhoneNumberBinding struct { Number, Provider string; Meta map[string]interface{} }
type DeviceCertificate struct { CertPEM string }
type PlayServicesProfile struct { HasPlayServices bool; PlayID string }
type DeviceInput struct { Type string; Data map[string]interface{} }
type DeviceState string
const ( StatePending DeviceState = "PENDING"; StateActive DeviceState = "ACTIVE"; StateSuspended DeviceState = "SUSPENDED"; StateRetired DeviceState = "RETIRED" )
