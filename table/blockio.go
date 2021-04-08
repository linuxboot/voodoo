package table

const BlockioGUID = "1D85CD7F-F43D-11D2-9A0C-0090273FC14D"

const (
	BlockioRevision    = 0
	BlockioMedia       = 0x8
	BlockioReset       = 0x10
	BlockioReadBlocks  = 0x18
	BlockioWriteBlocks = 0x20
	BlockioFlushBlocks = 0x28
)

var BlockioServiceNames = map[uint64]*val{
	CollRevision:    &val{N: "Revision"},
	CollMedia:       &val{N: "Media"},
	CollReset:       &val{N: "Reset"},
	CollReadBlocks:  &val{N: "ReadBlocks"},
	CollWriteBlocks: &val{N: "WriteBlocks"},
	CollFlushBlocks: &val{N: "FlushBlocks"},
}
