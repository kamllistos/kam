// Package report renders an analyze.Report for terminals, pull requests and machines.
package report

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/kamllistos/kam/internal/analyze"
)

// TextOptions control terminal output.
type TextOptions struct {
	Color       bool
	ShowRemoved bool
}

// Text writes a human-readable report for a terminal.
func Text(w io.Writer, r *analyze.Report, o TextOptions) error {
	p := painter{o.Color}
	bw := bufio.NewWriter(w)

	header := "kam diff"
	if r.TerraformVersion != "" {
		header += " · terraform " + r.TerraformVersion
	}
	header += fmt.Sprintf(" · %d IAM %s in plan", r.IAMResources, plural(r.IAMResources, "resource", "resources"))
	fmt.Fprintln(bw, p.bold(header))
	fmt.Fprintln(bw)

	switch {
	case r.IAMResources == 0:
		fmt.Fprintln(bw, "No AWS IAM resources in this plan.")
		return bw.Flush()
	case len(r.Principals) == 0:
		fmt.Fprintln(bw, p.color(green, "✓ No change to effective IAM access."))
		writeWarnings(bw, p, r.Warnings)
		return bw.Flush()
	}

	fmt.Fprintf(bw, "%d %s with access changes: %s\n\n", len(r.Principals),
		plural(len(r.Principals), "principal", "principals"), summary(r, func(s analyze.Severity, n int) string {
			return p.sev(s, fmt.Sprintf("%d %s", n, s))
		}))

	for _, pd := range r.Principals {
		name := p.bold(pd.Principal.Key)
		if pd.Principal.Address != "" {
			name += p.dim(" (" + pd.Principal.Address + ")")
		}
		fmt.Fprintf(bw, "%s  %s  %s\n", p.sev(pd.Severity, fmt.Sprintf("%-8s", strings.ToUpper(pd.Severity.String()))), name, p.dim(pd.Status))

		if pd.Status == "removed" {
			fmt.Fprintf(bw, "    %s\n\n", p.dim(fmt.Sprintf("principal is deleted: %d %s and %d trust %s go away",
				len(pd.Removed), plural(len(pd.Removed), "permission", "permissions"),
				len(pd.TrustRemoved), plural(len(pd.TrustRemoved), "entry", "entries"))))
			continue
		}

		for _, f := range pd.Findings {
			fmt.Fprintf(bw, "    %s %s\n", p.sev(f.Severity, "▲ "+f.Severity.String()), f.Title)
			if f.Detail != "" {
				fmt.Fprintf(bw, "      %s\n", p.dim(f.Detail))
			}
		}

		if len(pd.TrustAdded) > 0 {
			fmt.Fprintf(bw, "    %s\n", p.bold("can now be assumed by"))
			for _, t := range pd.TrustAdded {
				line := fmt.Sprintf("      + %s %s", t.Type, t.Principal)
				if t.Condition != "" {
					line += p.dim("  if " + t.Condition)
				}
				fmt.Fprintln(bw, line+tag(p, t.Severity))
			}
		}

		if len(pd.Added) > 0 {
			fmt.Fprintf(bw, "    %s\n", p.bold("new permissions"))
			writeChanges(bw, p, pd.Added, "+")
		}

		if len(pd.Removed)+len(pd.TrustRemoved) > 0 {
			if o.ShowRemoved {
				fmt.Fprintf(bw, "    %s\n", p.bold("removed"))
				for _, t := range pd.TrustRemoved {
					fmt.Fprintf(bw, "      - trust %s %s\n", t.Type, t.Principal)
				}
				writeChanges(bw, p, pd.Removed, "-")
			} else {
				fmt.Fprintf(bw, "    %s\n", p.dim(fmt.Sprintf("%d removed (use --show-removed to list)", len(pd.Removed)+len(pd.TrustRemoved))))
			}
		}
		fmt.Fprintln(bw)
	}
	writeWarnings(bw, p, r.Warnings)
	return bw.Flush()
}

// writeChanges groups permissions by the policy they come from.
func writeChanges(w io.Writer, p painter, changes []analyze.AccessChange, sign string) {
	var order []string
	byVia := map[string][]analyze.AccessChange{}
	for _, c := range changes {
		if _, ok := byVia[c.Via]; !ok {
			order = append(order, c.Via)
		}
		byVia[c.Via] = append(byVia[c.Via], c)
	}
	for _, via := range order {
		fmt.Fprintf(w, "      %s\n", p.dim(via))
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		for _, c := range byVia[via] {
			if c.Opaque {
				fmt.Fprintf(tw, "        %s (policy contents not visible to kam)\t\t%s\n", sign, tag(p, c.Severity))
				continue
			}
			res := "on " + c.Resource
			if c.Condition != "" {
				res += " (conditional)"
			}
			fmt.Fprintf(tw, "        %s %s\t%s\t%s\n", sign, c.Action, res, tag(p, c.Severity))
		}
		tw.Flush()
	}
}

func writeWarnings(w io.Writer, p painter, warnings []string) {
	for _, msg := range warnings {
		fmt.Fprintf(w, "%s %s\n", p.color(yellow, "warning:"), msg)
	}
}

func tag(p painter, s analyze.Severity) string {
	if s == analyze.Info {
		return ""
	}
	return "  " + p.sev(s, "["+s.String()+"]")
}

// summary lists principal counts per severity, highest first.
func summary(r *analyze.Report, format func(analyze.Severity, int) string) string {
	counts := map[analyze.Severity]int{}
	for _, pd := range r.Principals {
		counts[pd.Severity]++
	}
	var parts []string
	for s := analyze.Critical; s >= analyze.Info; s-- {
		if counts[s] > 0 {
			parts = append(parts, format(s, counts[s]))
		}
	}
	return strings.Join(parts, " · ")
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

const (
	red     = "31"
	green   = "32"
	yellow  = "33"
	blue    = "34"
	magenta = "35"
)

type painter struct{ on bool }

func (p painter) wrap(code, s string) string {
	if !p.on {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func (p painter) color(c, s string) string { return p.wrap(c, s) }
func (p painter) bold(s string) string     { return p.wrap("1", s) }
func (p painter) dim(s string) string      { return p.wrap("2", s) }

func (p painter) sev(s analyze.Severity, text string) string {
	switch s {
	case analyze.Critical:
		return p.wrap("1;"+red, text)
	case analyze.High:
		return p.wrap(magenta, text)
	case analyze.Medium:
		return p.wrap(yellow, text)
	case analyze.Low:
		return p.wrap(blue, text)
	default:
		return p.dim(text)
	}
}
