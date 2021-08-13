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
	STOutReset:             {N: "Reset"},
	STOutOutputString:      {N: "OutputString"},
	STOutTestString:        {N: "TestString"},
	STOutQueryMode:         {N: "QueryMode"},
	STOutSetMode:           {N: "SetMode"},
	STOutSetAttribute:      {N: "SetAttribute"},
	STOutClearScreen:       {N: "ClearScreen"},
	STOutSetCursorPosition: {N: "SetCursorPosition"},
	STOutEnableCursor:      {N: "EnableCursor"},
	STOutMode:              {N: "Mode"},
}

const (
	STInReset         = 0
	STInReadKeyStroke = 0x8
	STInWaitForKey    = 0x10
)

var SimpleTextInServicesNames = map[uint64]*val{
	STInReset:         {N: "Reset"},
	STInReadKeyStroke: {N: "ReadKeyStroke"},
	STInWaitForKey:    {N: "WaitForKey"},
}

const (
	STModeMaxMode       = 0
	STModeMode          = 0x4
	STModeAttribute     = 0x8
	STModeCursorColumn  = 0xc
	STModeCursorRow     = 0x10
	STModeCursorVisible = 0x14
)

var SimpleTextModeServicesNames = map[uint64]*val{
	STModeMaxMode:       {N: "MaxMode"},
	STModeMode:          {N: "Mode"},
	STModeAttribute:     {N: "Attribute"},
	STModeCursorColumn:  {N: "CursorColumn"},
	STModeCursorRow:     {N: "CursorRow"},
	STModeCursorVisible: {N: "CursorVisible"},
}
