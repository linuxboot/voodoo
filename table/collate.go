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
	CollStriColl:           &val{N: "StriColl"},
	CollMetaiMatch:         &val{N: "MetaiMatch"},
	CollStrLwr:             &val{N: "StrLwr"},
	CollStrUpr:             &val{N: "StrUpr"},
	CollFatToStr:           &val{N: "FatToStr"},
	CollStrToFat:           &val{N: "StrToFat"},
	CollSupportedLanguages: &val{N: "SupportedLanguages"},
}
