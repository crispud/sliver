package encoders

import (
	encutil "github.com/bishopfox/sliver/util/encoders"
)

const MimicEncoderID = uint64(99999)

func init() {
	cfg := encutil.DefaultMimicConfig()
	mimic, _ := encutil.NewMimicEncoding(cfg)
	EncoderMap[MimicEncoderID] = mimic
	FastEncoderMap[MimicEncoderID] = mimic
}
