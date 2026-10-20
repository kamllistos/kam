package analyze

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Severity ranks how much a change matters, from Info to Critical.
type Severity int

// Severity levels in increasing order.
const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

var severityNames = [...]string{"info", "low", "medium", "high", "critical"}

func (s Severity) String() string {
	if s < Info || s > Critical {
		return fmt.Sprintf("severity(%d)", int(s))
	}
	return severityNames[s]
}

// MarshalJSON encodes a severity as its name.
func (s Severity) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// ParseSeverity parses a severity name such as "high".
func ParseSeverity(name string) (Severity, error) {
	for i, n := range severityNames {
		if strings.EqualFold(name, n) {
			return Severity(i), nil
		}
	}
	return Info, fmt.Errorf("unknown severity %q (want info, low, medium, high or critical)", name)
}
