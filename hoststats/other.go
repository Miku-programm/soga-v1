//go:build !linux

package hoststats

import (
	"encoding/json"
	"errors"
	"reconstructed.local/soga/panel"
)

type Sampler struct{}

func New() *Sampler { return new(Sampler) }
func (*Sampler) Read(string) (panel.Status, error) {
	return panel.Status{}, errors.New("host status collection currently requires Linux")
}
func (*Sampler) ReadDJExtras([3]float64) (map[string]json.RawMessage, error) {
	return nil, errors.New("DJ host metrics currently require Linux")
}
