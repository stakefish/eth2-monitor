package opts

var (
	LogLevel       string
	BeaconChainAPI string
	MetricsPort    string
	SlackURL       string
	SlackUsername  string

	Monitor struct {
		ReplayEpoch       []uint
		SinceEpoch        uint64
		PrintSuccessful   bool
		MEVRelaysFilePath string

		Pubkeys []string
	}
)
