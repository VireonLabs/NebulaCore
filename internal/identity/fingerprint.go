package identity
type DigitalFingerprint struct { OS, Model, CPU, GPU, Region, City, Hash string }
func NewDigitalFingerprint(os, model, cpu, gpu, region, city string, seed []byte, hasher Hasher) DigitalFingerprint { return DigitalFingerprint{} }
