package pkg

import (
	"eth2-monitor/spec"
)

var epochsChan chan spec.Epoch

func init() {
	epochsChan = make(chan spec.Epoch)
}
