package table

const (
	CollStriColl           = 0
	CollMetaiMatch         = 0x8
	CollStrLwr             = 0x10
	CollStrUpr             = 0x18
	CollFatToStr           = 0x20
	CollStrToFat           = 0x28
	CollSupportedLanguages = 0x30
)

var CollateServicesNames = map[uint64]*val{
	CollStriColl:           {N: "StriColl"},
	CollMetaiMatch:         {N: "MetaiMatch"},
	CollStrLwr:             {N: "StrLwr"},
	CollStrUpr:             {N: "StrUpr"},
	CollFatToStr:           {N: "FatToStr"},
	CollStrToFat:           {N: "StrToFat"},
	CollSupportedLanguages: {N: "SupportedLanguages"},
}
