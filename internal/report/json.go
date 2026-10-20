package report

import (
	"encoding/json"
	"io"

	"github.com/kamllistos/kam/internal/analyze"
)

// JSON writes the report as indented JSON for other tools to consume.
func JSON(w io.Writer, r *analyze.Report) error {
	if r.Principals == nil {
		r.Principals = []analyze.PrincipalDiff{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
