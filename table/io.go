package table

const (
	STOutReset             = 0
	STOutOutputString      = 0x8
	STOutTestString        = 0x10
	STOutQueryMode         = 0x18
	STOutSetMode           = 0x20
	STOutSetAttribute      = 0x28
	STOutClearScreen       = 0x30
	STOutSetCursorPosition = 0x38
	STOutEnableCursor      = 0x40
	STOutMode              = 0x48
)

var SimpleTextOutServicesNames = map[uint64]*val{
	STOutReset:             &val{N: "Reset"},
	STOutOutputString:      &val{N: "OutputString"},
	STOutTestString:        &val{N: "TestString"},
	STOutQueryMode:         &val{N: "QueryMode"},
	STOutSetMode:           &val{N: "SetMode"},
	STOutSetAttribute:      &val{N: "SetAttribute"},
	STOutClearScreen:       &val{N: "ClearScreen"},
	STOutSetCursorPosition: &val{N: "SetCursorPosition"},
	STOutEnableCursor:      &val{N: "EnableCursor"},
	STOutMode:              &val{N: "Mode"},
}

const (
	STInReset         = 0
	STInReadKeyStroke = 0x8
	STInWaitForKey    = 0x10
)

var SimpleTextInServicesNames = map[uint64]*val{
	STInReset:         &val{N: "Reset"},
	STInReadKeyStroke: &val{N: "ReadKeyStroke"},
	STInWaitForKey:    &val{N: "WaitForKey"},
}
