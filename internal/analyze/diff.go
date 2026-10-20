// Package analyze works out how a Terraform plan changes who can do what in
// AWS IAM, and how much each change matters.
package analyze

import (
	"sort"
	"strings"

	"github.com/kamllistos/kam/internal/policy"
	"github.com/kamllistos/kam/internal/tfplan"
)

// Options tune the analysis.
type Options struct {
	// OwnAccounts are AWS account IDs the user controls. Trust from any other
	// account is reported as external.
	OwnAccounts []string
}

// Report is the result of diffing a plan.
type Report struct {
	TerraformVersion string          `json:"terraform_version,omitempty"`
	IAMResources     int             `json:"iam_resources"`
	MaxSeverity      Severity        `json:"max_severity"`
	Principals       []PrincipalDiff `json:"principals"`
	Warnings         []string        `json:"warnings,omitempty"`
}

// PrincipalDiff is how one role, user or group's access changes.
type PrincipalDiff struct {
	Principal    Principal      `json:"principal"`
	Status       string         `json:"status"` // new, changed or removed
	Severity     Severity       `json:"severity"`
	Findings     []Finding      `json:"findings,omitempty"`
	Added        []AccessChange `json:"added,omitempty"`
	Removed      []AccessChange `json:"removed,omitempty"`
	TrustAdded   []TrustChange  `json:"trust_added,omitempty"`
	TrustRemoved []TrustChange  `json:"trust_removed,omitempty"`
}

// Finding is a risk rule triggered by the plan.
type Finding struct {
	Severity Severity `json:"severity"`
	Rule     string   `json:"rule"`
	Title    string   `json:"title"`
	Detail   string   `json:"detail,omitempty"`
	Evidence []string `json:"evidence,omitempty"`
}

// AccessChange is one permission gained or lost.
type AccessChange struct {
	Action    string   `json:"action"`
	Resource  string   `json:"resource"`
	Condition string   `json:"condition,omitempty"`
	Via       string   `json:"via"`
	Severity  Severity `json:"severity"`
	Opaque    bool     `json:"opaque,omitempty"`
}

// TrustChange is a principal gaining or losing the right to assume a role.
type TrustChange struct {
	Type      string   `json:"type"`
	Principal string   `json:"principal"`
	Condition string   `json:"condition,omitempty"`
	Via       string   `json:"via"`
	Severity  Severity `json:"severity"`
}

// Diff compares effective IAM access before and after the plan.
func Diff(p *tfplan.Plan, opt Options) *Report {
	b, a := build(p, before), build(p, after)
	rep := &Report{TerraformVersion: p.TerraformVersion}
	for _, rc := range p.ResourceChanges {
		if rc.Mode == "managed" && strings.HasPrefix(rc.Type, "aws_iam_") {
			rep.IAMResources++
		}
	}

	keys := map[string]bool{}
	for k := range b.principals {
		keys[k] = true
	}
	for k := range a.principals {
		keys[k] = true
	}
	for k := range keys {
		pd, changed := diffPrincipal(b.principals[k], a.principals[k], opt)
		if !changed {
			continue
		}
		rep.Principals = append(rep.Principals, pd)
		if pd.Severity > rep.MaxSeverity {
			rep.MaxSeverity = pd.Severity
		}
	}
	sort.Slice(rep.Principals, func(i, j int) bool {
		pi, pj := rep.Principals[i], rep.Principals[j]
		if pi.Severity != pj.Severity {
			return pi.Severity > pj.Severity
		}
		return pi.Principal.Key < pj.Principal.Key
	})

	warnings := map[string]bool{}
	for w := range b.warnings {
		warnings[w] = true
	}
	for w := range a.warnings {
		warnings[w] = true
	}
	for w := range warnings {
		rep.Warnings = append(rep.Warnings, w)
	}
	sort.Strings(rep.Warnings)
	return rep
}

func diffPrincipal(b, a *principalState, opt Options) (PrincipalDiff, bool) {
	var pd PrincipalDiff
	switch {
	case b != nil && b.defined && (a == nil || !a.defined):
		pd.Status, pd.Principal = "removed", b.Principal
	case a != nil && a.defined && (b == nil || !b.defined):
		pd.Status, pd.Principal = "new", a.Principal
	default:
		pd.Status = "changed"
		if a != nil {
			pd.Principal = a.Principal
		} else {
			pd.Principal = b.Principal
		}
	}

	var bAllow, aAllow []grant
	var bTrust, aTrust []trustEntry
	if b != nil {
		bAllow, bTrust = effective(b.grants), b.trust
	}
	if a != nil {
		aAllow, aTrust = effective(a.grants), a.trust
	}

	findings := map[string]*Finding{}
	raise := func(h hit, evidence string) {
		f, ok := findings[h.rule]
		if !ok {
			f = &Finding{Rule: h.rule, Severity: h.sev, Title: h.title, Detail: h.detail}
			findings[h.rule] = f
		}
		if h.sev > f.Severity {
			f.Severity, f.Title, f.Detail = h.sev, h.title, h.detail
		}
		if evidence != "" && !contains(f.Evidence, evidence) {
			f.Evidence = append(f.Evidence, evidence)
		}
	}

	var added []grant
	for _, g := range aAllow {
		if grantedBy(bAllow, g) {
			continue
		}
		added = append(added, g)
		sev := baseSeverity(g)
		for _, h := range classify(g) {
			raise(h, g.actionLabel()+" on "+g.resourceLabel())
			if h.sev > sev {
				sev = h.sev
			}
		}
		pd.Added = append(pd.Added, change(g, sev))
	}
	for _, g := range bAllow {
		if !grantedBy(aAllow, g) {
			pd.Removed = append(pd.Removed, change(g, Info))
		}
	}

	// iam:PassRole is only dangerous next to something that launches compute
	// with the passed role, so check the combination across all after grants.
	// An administrator can do this anyway, so it would only be noise there.
	_, admin := findings["admin"]
	_, notActionAdmin := findings["notaction-admin"]
	if !admin && !notActionAdmin && anyBroad(aAllow, "iam:PassRole") {
		var launch []string
		for _, act := range launchWithRole {
			if anyAllows(aAllow, act) {
				launch = append(launch, act)
			}
		}
		if len(launch) > 0 && (anyAllows(added, "iam:PassRole") || anyAllowsOf(added, launch)) {
			raise(hit{"passrole-compute", Critical, "Privilege escalation: iam:PassRole plus " + launch[0],
				"Can start compute with any role it can pass and run code with that role's permissions, including roles more privileged than itself."},
				"iam:PassRole + "+strings.Join(launch, ", "))
		}
	}

	beforeTrust := map[string]bool{}
	for _, t := range bTrust {
		beforeTrust[t.key()] = true
	}
	afterTrust := map[string]bool{}
	for _, t := range aTrust {
		afterTrust[t.key()] = true
		if beforeTrust[t.key()] {
			continue
		}
		h := classifyTrust(t, opt.OwnAccounts)
		if h.sev > Info {
			raise(h, t.typ+" "+t.value)
		}
		pd.TrustAdded = append(pd.TrustAdded, TrustChange{Type: t.typ, Principal: t.value, Condition: t.condition, Via: t.via, Severity: h.sev})
	}
	for _, t := range bTrust {
		if !afterTrust[t.key()] {
			pd.TrustRemoved = append(pd.TrustRemoved, TrustChange{Type: t.typ, Principal: t.value, Condition: t.condition, Via: t.via})
		}
	}

	for _, f := range findings {
		pd.Findings = append(pd.Findings, *f)
		if f.Severity > pd.Severity {
			pd.Severity = f.Severity
		}
	}
	for _, c := range pd.Added {
		if c.Severity > pd.Severity {
			pd.Severity = c.Severity
		}
	}
	sort.Slice(pd.Findings, func(i, j int) bool {
		if pd.Findings[i].Severity != pd.Findings[j].Severity {
			return pd.Findings[i].Severity > pd.Findings[j].Severity
		}
		return pd.Findings[i].Rule < pd.Findings[j].Rule
	})

	changed := len(pd.Added)+len(pd.Removed)+len(pd.TrustAdded)+len(pd.TrustRemoved) > 0
	return pd, changed
}

func change(g grant, sev Severity) AccessChange {
	c := AccessChange{Action: g.actionLabel(), Resource: g.resourceLabel(), Condition: g.condition, Via: g.via, Severity: sev, Opaque: g.opaque}
	if g.opaque {
		c.Via = g.label + ", " + g.via
	}
	return c
}

// effective drops Allow grants that an unconditional Deny fully cancels.
func effective(gs []grant) []grant {
	var denies, out []grant
	for _, g := range gs {
		if g.effect == "Deny" && !g.opaque && g.condition == "" {
			d := g
			d.effect = "Allow"
			denies = append(denies, d)
		}
	}
	for _, g := range gs {
		if g.effect != "Allow" {
			continue
		}
		denied := false
		for _, d := range denies {
			if covers(d, g) {
				denied = true
				break
			}
		}
		if !denied {
			out = append(out, g)
		}
	}
	return out
}

// grantedBy reports whether g was already allowed by some grant in set.
func grantedBy(set []grant, g grant) bool {
	for _, s := range set {
		if g.opaque {
			if s.opaque && s.label == g.label && s.via == g.via {
				return true
			}
			continue
		}
		if covers(s, g) {
			return true
		}
	}
	return false
}

// covers reports whether grant b allows everything grant a allows.
func covers(b, a grant) bool {
	if b.opaque || a.opaque {
		return false
	}
	if b.condition != "" && b.condition != a.condition {
		return false
	}
	if !coversResource(b, a) {
		return false
	}
	switch {
	case len(a.notActions) > 0:
		if len(b.notActions) > 0 {
			// b is at least as broad if everything b excludes, a excludes too.
			for _, bn := range b.notActions {
				if !excludesPattern(a.notActions, bn) {
					return false
				}
			}
			return true
		}
		return b.action == "*"
	case len(b.notActions) > 0:
		for _, na := range b.notActions {
			if policy.CoversAction(na, a.action) || policy.CoversAction(a.action, na) {
				return false
			}
		}
		return true
	default:
		return policy.CoversAction(b.action, a.action)
	}
}

func coversResource(b, a grant) bool {
	switch {
	case len(a.notResources) > 0:
		return b.resource == "*" || strings.Join(b.notResources, "\x00") == strings.Join(a.notResources, "\x00")
	case len(b.notResources) > 0:
		for _, nr := range b.notResources {
			if policy.CoversResource(nr, a.resource) || policy.CoversResource(a.resource, nr) {
				return false
			}
		}
		return true
	default:
		return policy.CoversResource(b.resource, a.resource)
	}
}

func excludesPattern(notActions []string, pattern string) bool {
	for _, na := range notActions {
		if policy.CoversAction(na, pattern) {
			return true
		}
	}
	return false
}

func anyAllows(gs []grant, action string) bool {
	for _, g := range gs {
		if allowsAction(g, action) {
			return true
		}
	}
	return false
}

func anyAllowsOf(gs []grant, actions []string) bool {
	for _, a := range actions {
		if anyAllows(gs, a) {
			return true
		}
	}
	return false
}

func anyBroad(gs []grant, action string) bool {
	for _, g := range gs {
		if allowsAction(g, action) && isBroad(g) {
			return true
		}
	}
	return false
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
