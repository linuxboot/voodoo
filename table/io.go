package table

const (
	STReset             = 0
	STOutputString      = 0x8
	STTestString        = 0x10
	STQueryMode         = 0x18
	STSetMode           = 0x20
	STSetAttribute      = 0x28
	STClearScreen       = 0x30
	STSetCursorPosition = 0x38
	STEnableCursor      = 0x40
	STMode              = 0x48
)

var SimpleTextServicesNames = map[uint64]*val{
	STReset:             &val{N: "Reset"},
	STOutputString:      &val{N: "OutputString"},
	STTestString:        &val{N: "TestString"},
	STQueryMode:         &val{N: "QueryMode"},
	STSetMode:           &val{N: "SetMode"},
	STSetAttribute:      &val{N: "SetAttribute"},
	STClearScreen:       &val{N: "ClearScreen"},
	STSetCursorPosition: &val{N: "SetCursorPosition"},
	STEnableCursor:      &val{N: "EnableCursor"},
	STMode:              &val{N: "Mode"},
}
