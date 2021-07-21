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

type BlockIOMediaInfo struct {
	MediaId          uint32
	RemovableMedia   uint32
	MediaPresent     uint32
	LogicalPartition uint32
	ReadOnly         uint32
	WriteCaching     uint32
	BlockSize        uint32
	IoAlign          uint32
	LastBlock        uint64
}

var BlockIOServiceNames = map[uint64]*val{
	BlockIORevision:    &val{N: "Revision"},
	BlockIOMedia:       &val{N: "Media"},
	BlockIOReset:       &val{N: "Reset"},
	BlockIOReadBlocks:  &val{N: "ReadBlocks"},
	BlockIOWriteBlocks: &val{N: "WriteBlocks"},
	BlockIOFlushBlocks: &val{N: "FlushBlocks"},
}
