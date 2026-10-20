// Package cli implements kam's command line.
package cli

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/kamllistos/kam/internal/analyze"
	"github.com/kamllistos/kam/internal/report"
	"github.com/kamllistos/kam/internal/tfplan"
)

// Version and Commit are set at build time with -ldflags.
var (
	Version = "dev"
	Commit  = ""
)

const usage = `kam explains what IAM access a Terraform plan grants, before you apply it.

Usage:
  kam diff [flags] <plan.json | tfplan | ->
  kam version

Create plan JSON with:
  terraform plan -out tfplan && terraform show -json tfplan > plan.json

Run "kam diff -h" for flags.
`

// Exit codes.
const (
	exitOK       = 0
	exitFindings = 1 // a principal reached the --fail-on severity
	exitError    = 2
)

// Run executes kam with args (without the program name) and returns the exit code.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitError
	}
	switch args[0] {
	case "diff":
		return runDiff(args[1:], stdin, stdout, stderr)
	case "version", "--version", "-v":
		v := "kam " + Version
		if Commit != "" {
			v += " (" + Commit + ")"
		}
		fmt.Fprintln(stdout, v)
		return exitOK
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return exitOK
	default:
		fmt.Fprintf(stderr, "kam: unknown command %q\n\n%s", args[0], usage)
		return exitError
	}
}

func runDiff(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("kam diff", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "text", "output `format`: text, markdown or json")
	fs.StringVar(format, "f", "text", "shorthand for -format")
	failOn := fs.String("fail-on", "none", "exit 1 when any principal reaches this `severity` (low, medium, high, critical, none)")
	accounts := fs.String("account", "", "comma-separated AWS account `IDs` you own; trust from other accounts is flagged as external")
	minSev := fs.String("min-severity", "info", "hide principals below this `severity`")
	showRemoved := fs.Bool("show-removed", false, "list permissions the plan removes (text output)")
	noColor := fs.Bool("no-color", false, "disable colored output (also honours NO_COLOR)")
	fs.Usage = func() {
		fmt.Fprint(stderr, "Usage: kam diff [flags] <plan.json | tfplan | ->\n\nFlags:\n")
		fs.PrintDefaults()
	}

	// Accept flags before and after the plan path.
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return exitOK
			}
			return exitError
		}
		if fs.NArg() == 0 {
			break
		}
		positional = append(positional, fs.Arg(0))
		args = fs.Args()[1:]
	}

	threshold, failEnabled := analyze.Critical+1, false
	if !strings.EqualFold(*failOn, "none") {
		s, err := analyze.ParseSeverity(*failOn)
		if err != nil {
			fmt.Fprintf(stderr, "kam: --fail-on: %v\n", err)
			return exitError
		}
		threshold, failEnabled = s, true
	}
	floor, err := analyze.ParseSeverity(*minSev)
	if err != nil {
		fmt.Fprintf(stderr, "kam: --min-severity: %v\n", err)
		return exitError
	}

	var path string
	switch len(positional) {
	case 0:
		if isTerminal(stdin) {
			fs.Usage()
			return exitError
		}
		path = "-"
	case 1:
		path = positional[0]
	default:
		fmt.Fprintln(stderr, "kam: diff takes one plan file")
		return exitError
	}

	plan, err := readPlan(path, stdin)
	if err != nil {
		fmt.Fprintf(stderr, "kam: %v\n", err)
		return exitError
	}

	var own []string
	for _, a := range strings.Split(*accounts, ",") {
		if a = strings.TrimSpace(a); a != "" {
			own = append(own, a)
		}
	}
	rep := analyze.Diff(plan, analyze.Options{OwnAccounts: own})
	code := exitOK
	if failEnabled && len(rep.Principals) > 0 && rep.MaxSeverity >= threshold {
		code = exitFindings
	}

	shown := rep.Principals[:0:0]
	for _, pd := range rep.Principals {
		if pd.Severity >= floor {
			shown = append(shown, pd)
		}
	}
	rep.Principals = shown

	switch strings.ToLower(*format) {
	case "text":
		color := !*noColor && os.Getenv("NO_COLOR") == "" && isTerminal(stdout)
		err = report.Text(stdout, rep, report.TextOptions{Color: color, ShowRemoved: *showRemoved})
	case "markdown", "md":
		err = report.Markdown(stdout, rep)
	case "json":
		err = report.JSON(stdout, rep)
	default:
		fmt.Fprintf(stderr, "kam: unknown format %q (want text, markdown or json)\n", *format)
		return exitError
	}
	if err != nil {
		fmt.Fprintf(stderr, "kam: %v\n", err)
		return exitError
	}
	return code
}

// readPlan loads plan JSON from a file or stdin. A binary plan file
// (terraform plan -out) is converted with terraform show -json.
func readPlan(path string, stdin io.Reader) (*tfplan.Plan, error) {
	var data []byte
	var err error
	if path == "-" {
		data, err = io.ReadAll(stdin)
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, err
	}
	if bytes.HasPrefix(data, []byte("PK\x03\x04")) {
		if path == "-" {
			return nil, errors.New("got a binary plan on stdin; pass its path instead, or pipe terraform show -json tfplan")
		}
		if data, err = showJSON(path); err != nil {
			return nil, err
		}
	}
	return tfplan.Load(bytes.NewReader(data))
}

func showJSON(path string) ([]byte, error) {
	for _, bin := range []string{"terraform", "tofu"} {
		exe, err := exec.LookPath(bin)
		if err != nil {
			continue
		}
		var stderr bytes.Buffer
		cmd := exec.Command(exe, "show", "-json", path)
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("%s show -json %s: %v: %s (run kam from the initialised Terraform directory)", bin, path, err, strings.TrimSpace(stderr.String()))
		}
		return out, nil
	}
	return nil, fmt.Errorf("%s is a binary plan and neither terraform nor tofu is on PATH; convert it with terraform show -json", path)
}

func isTerminal(v any) bool {
	f, ok := v.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
