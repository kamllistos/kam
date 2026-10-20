package analyze

import (
	"os"
	"testing"

	"github.com/kamllistos/kam/internal/tfplan"
)

func loadPlan(t *testing.T, path string) *tfplan.Plan {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	p, err := tfplan.Load(f)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func principal(t *testing.T, r *Report, key string) PrincipalDiff {
	t.Helper()
	for _, pd := range r.Principals {
		if pd.Principal.Key == key {
			return pd
		}
	}
	t.Fatalf("no diff for %s; got %v", key, keys(r))
	return PrincipalDiff{}
}

func keys(r *Report) []string {
	var out []string
	for _, pd := range r.Principals {
		out = append(out, pd.Principal.Key)
	}
	return out
}

func hasRule(pd PrincipalDiff, rule string, sev Severity) bool {
	for _, f := range pd.Findings {
		if f.Rule == rule && f.Severity == sev {
			return true
		}
	}
	return false
}

func TestSamplePlan(t *testing.T) {
	r := Diff(loadPlan(t, "../../testdata/plan.json"), Options{})

	if r.MaxSeverity != Critical {
		t.Errorf("MaxSeverity = %v, want critical", r.MaxSeverity)
	}
	if r.IAMResources != 13 {
		t.Errorf("IAMResources = %d, want 13 (the S3 bucket is not IAM)", r.IAMResources)
	}

	alice := principal(t, r, "user/alice")
	if !hasRule(alice, "admin", Critical) {
		t.Errorf("alice joining admins should be a critical admin finding: %+v", alice.Findings)
	}

	ci := principal(t, r, "role/ci-deploy")
	for _, rule := range []string{"github-oidc-unscoped", "passrole-compute"} {
		if !hasRule(ci, rule, Critical) {
			t.Errorf("role/ci-deploy missing critical %s: %+v", rule, ci.Findings)
		}
	}
	if len(ci.Added) != 3 {
		t.Errorf("role/ci-deploy gained %d permissions, want 3 (the S3 ones existed before): %+v", len(ci.Added), ci.Added)
	}

	analytics := principal(t, r, "role/analytics-reader")
	if analytics.Status != "new" {
		t.Errorf("analytics-reader status = %s, want new", analytics.Status)
	}
	if !hasRule(analytics, "data-read-broad", High) {
		t.Errorf("secretsmanager:GetSecretValue on * should be high: %+v", analytics.Findings)
	}
	if !hasRule(analytics, "cross-account-trust", Medium) {
		t.Errorf("trust from 444455556666 without --account should be medium: %+v", analytics.Findings)
	}

	legacy := principal(t, r, "role/legacy-batch")
	if legacy.Status != "removed" || legacy.Severity != Info || len(legacy.Removed) == 0 {
		t.Errorf("legacy-batch = %+v, want removed/info with removed grants", legacy)
	}

	for _, pd := range r.Principals {
		if pd.Principal.Key == "group/admins" || pd.Principal.Key == "group/developers" {
			t.Errorf("%s did not change but was reported", pd.Principal.Key)
		}
	}
	if len(r.Warnings) != 0 {
		t.Errorf("unexpected warnings: %v", r.Warnings)
	}
}

func TestOwnAccountsMarkExternalTrust(t *testing.T) {
	r := Diff(loadPlan(t, "../../testdata/plan.json"), Options{OwnAccounts: []string{"111122223333"}})
	if !hasRule(principal(t, r, "role/analytics-reader"), "external-trust", High) {
		t.Error("444455556666 is not an own account, so its trust should be high")
	}
	r = Diff(loadPlan(t, "../../testdata/plan.json"), Options{OwnAccounts: []string{"444455556666"}})
	if pd := principal(t, r, "role/analytics-reader"); hasRule(pd, "cross-account-trust", Medium) || hasRule(pd, "external-trust", High) {
		t.Errorf("trust from an own account should not be flagged: %+v", pd.Findings)
	}
}

func TestCoverage(t *testing.T) {
	g := func(action, resource string) grant { return grant{effect: "Allow", action: action, resource: resource} }
	tests := []struct {
		name string
		b, a grant
		want bool
	}{
		{"wildcard covers specific", g("s3:*", "*"), g("s3:GetObject", "arn:aws:s3:::b/*"), true},
		{"specific does not cover wildcard", g("s3:GetObject", "*"), g("s3:*", "*"), false},
		{"resource narrower", g("s3:*", "arn:aws:s3:::b/*"), g("s3:GetObject", "*"), false},
		{"NotAction covers unrelated", grant{effect: "Allow", notActions: []string{"iam:*"}, resource: "*"}, g("s3:GetObject", "*"), true},
		{"NotAction does not cover excluded", grant{effect: "Allow", notActions: []string{"iam:*"}, resource: "*"}, g("iam:PassRole", "*"), false},
		{"conditional does not cover unconditional", grant{effect: "Allow", action: "*", resource: "*", condition: "x"}, g("s3:GetObject", "*"), false},
	}
	for _, tt := range tests {
		if got := covers(tt.b, tt.a); got != tt.want {
			t.Errorf("%s: covers = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestDenyCancelsAllow(t *testing.T) {
	gs := []grant{
		{effect: "Allow", action: "s3:*", resource: "*"},
		{effect: "Deny", action: "s3:DeleteBucket", resource: "*"},
		{effect: "Allow", action: "s3:DeleteBucket", resource: "arn:aws:s3:::b"},
	}
	eff := effective(gs)
	if len(eff) != 1 || eff[0].action != "s3:*" {
		t.Errorf("effective = %+v, want only s3:* (the explicit DeleteBucket allow is denied)", eff)
	}
}

func TestBroadResource(t *testing.T) {
	tests := map[string]bool{
		"*":                                true,
		"arn:aws:iam::111122223333:role/*": true,
		"arn:aws:secretsmanager:eu-west-1:111122223333:secret:*": true,
		"arn:aws:s3:::acme-data/*":                               false,
		"arn:aws:s3:::*":                                         true,
		"arn:aws:iam::111122223333:role/ci":                      false,
	}
	for res, want := range tests {
		if got := broadResource(res); got != want {
			t.Errorf("broadResource(%q) = %v, want %v", res, got, want)
		}
	}
}
