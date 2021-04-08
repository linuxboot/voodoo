package table

const BlockIOGUID = "964E5B21-6459-11D2-8E39-00A0C969723B"

const (
	BlockIORevision    = 0
	BlockIOMedia       = 0x8
	BlockIOReset       = 0x10
	BlockIOReadBlocks  = 0x18
	BlockIOWriteBlocks = 0x20
	BlockIOFlushBlocks = 0x28
)

var BlockIOServiceNames = map[uint64]*val{
	BlockIORevision:    &val{N: "Revision"},
	BlockIOMedia:       &val{N: "Media"},
	BlockIOReset:       &val{N: "Reset"},
	BlockIOReadBlocks:  &val{N: "ReadBlocks"},
	BlockIOWriteBlocks: &val{N: "WriteBlocks"},
	BlockIOFlushBlocks: &val{N: "FlushBlocks"},
}
