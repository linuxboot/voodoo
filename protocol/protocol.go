package protocol

// A ProtocolHandle is a string'ed GUID and its associated []byte.
// They are created by init functions.
type ProtocolHandle struct {
	GUID string
	Data []byte
}

// CopyAble are ProtocolHandle with marshal'ed []byte that we can copy to the process memory.
var CopyAble = map[string]*ProtocolHandle{}
