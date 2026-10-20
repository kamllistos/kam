package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

const samplePlan = "../../testdata/plan.json"

func run(args ...string) (code int, stdout, stderr string) {
	var out, errOut bytes.Buffer
	code = Run(args, strings.NewReader(""), &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestDiffText(t *testing.T) {
	code, out, errOut := run("diff", samplePlan)
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, errOut)
	}
	for _, want := range []string{"CRITICAL", "user/alice", "Any GitHub repository can assume this role", "iam:PassRole"} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b[") {
		t.Error("output to a non-terminal must not contain color codes")
	}
}

func TestFailOn(t *testing.T) {
	if code, _, _ := run("diff", "--fail-on", "critical", samplePlan); code != exitFindings {
		t.Errorf("--fail-on critical: exit %d, want %d", code, exitFindings)
	}
	// Flags after the path work too.
	if code, _, _ := run("diff", samplePlan, "--fail-on=high", "-f", "json"); code != exitFindings {
		t.Errorf("--fail-on high after path: exit %d, want %d", code, exitFindings)
	}
	if code, _, _ := run("diff", "--fail-on", "nope", samplePlan); code != exitError {
		t.Errorf("bad severity: exit %d, want %d", code, exitError)
	}
}

func TestDiffJSONAndMarkdown(t *testing.T) {
	_, out, _ := run("diff", "-f", "json", samplePlan)
	var rep struct {
		MaxSeverity string `json:"max_severity"`
		Principals  []struct {
			Principal struct{ Key string } `json:"principal"`
		} `json:"principals"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if rep.MaxSeverity != "critical" || len(rep.Principals) != 4 {
		t.Errorf("got max %s with %d principals, want critical with 4", rep.MaxSeverity, len(rep.Principals))
	}

	_, md, _ := run("diff", "--format", "markdown", samplePlan)
	if !strings.HasPrefix(md, "<!-- kam-diff -->") || !strings.Contains(md, "| 🔴 | `user/alice`") {
		t.Errorf("unexpected markdown:\n%s", md)
	}
}

func TestMinSeverityHidesQuietPrincipals(t *testing.T) {
	_, out, _ := run("diff", "--min-severity", "high", samplePlan)
	if strings.Contains(out, "legacy-batch") {
		t.Errorf("--min-severity high should hide the info-level removal:\n%s", out)
	}
}

func TestRejectsNonPlanJSON(t *testing.T) {
	var errOut bytes.Buffer
	code := Run([]string{"diff", "-"}, strings.NewReader(`{"hello":"world"}`), &bytes.Buffer{}, &errOut)
	if code != exitError || !strings.Contains(errOut.String(), "terraform show -json") {
		t.Errorf("exit %d, stderr %q", code, errOut.String())
	}
}
