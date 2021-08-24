package uefi

import "github.com/linuxboot/fiano/pkg/guid"

const (
	LoadedImageProtocol                              = "5B1B31A1-9562-11D2-8E3F-00A0C969723B"
	ConsoleSupportTest_SimpleTextInputExProtocolTest = "DD9E7534-7762-4698-8C14-F58517A625AA"
)

var (
	BlockIOGUID                                          = guid.MustParse("964E5B21-6459-11D2-8E39-00A0C969723B")
	ConInGUID                                            = guid.MustParse("387477C1-69C7-11D2-8E39-0A00C969723B")
	ConOutGUID                                           = guid.MustParse("387477C2-69C7-11D2-8E39-0A00C969723B")
	DevicePathGUID                                       = guid.MustParse(DEVICE_PATH_GUID)
	LoadedImageGUID                                      = guid.MustParse(LoadedImageProtocol)
	ConsoleSupportTest_SimpleTextInputExProtocolTestGUID = guid.MustParse(ConsoleSupportTest_SimpleTextInputExProtocolTest)
)
