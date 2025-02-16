package protos

type RedirectType int

const (
	RedirectType_Dump RedirectType = iota + 1
	RedirectType_Remote
	RedirectType_Spoof
	RedirectType_Tap
)

const (
	RedirectTypeStr_Dump   = "dump"
	RedirectTypeStr_Remote = "remote"
	RedirectTypeStr_Spoof  = "spoof"
	RedirectTypeStr_Tap    = "tap"
)

var RedirectTypeStrLookup = map[RedirectType]string{
	RedirectType_Dump:   RedirectTypeStr_Dump,
	RedirectType_Remote: RedirectTypeStr_Remote,
	RedirectType_Spoof:  RedirectTypeStr_Spoof,
	RedirectType_Tap:    RedirectTypeStr_Tap,
}

var RedirectTypeLookup = map[string]RedirectType{
	RedirectTypeStr_Dump:   RedirectType_Dump,
	RedirectTypeStr_Remote: RedirectType_Remote,
	RedirectTypeStr_Spoof:  RedirectType_Spoof,
	RedirectTypeStr_Tap:    RedirectType_Tap,
}

func (t RedirectType) String() string {
	return RedirectTypeStrLookup[t]
}

func (t *RedirectType) Set(s string) error {
	*t = RedirectTypeLookup[s]
	return nil
}

func (t RedirectType) Type() string {
	return "RedirectType"
}

type RedirectDump struct {
	Data string `json:"data"`
}
