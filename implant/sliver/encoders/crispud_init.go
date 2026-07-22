package encoders

// Crispud Mimic Encoder — registered as a native encoder in Sliver.
// Wraps C2 payloads in HTTP-like JSON to evade signature detection.

var MimicEncoderID = uint64(99999)

var Mimic *MimicEncoding

func init() {
	cfg := DefaultMimicConfig()
	Mimic, _ = NewMimicEncoding(cfg)
	NativeEncoderMap[MimicEncoderID] = Mimic
}
