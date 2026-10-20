package analyze

import (
	"fmt"
	"sort"
	"strings"

	"github.com/kamllistos/kam/internal/policy"
	"github.com/kamllistos/kam/internal/tfplan"
)

// Principal identifies an IAM role, user or group.
type Principal struct {
	// Key is "role/NAME", "user/NAME" or "group/NAME". When the name is only
	// known after apply it is "role/<terraform address>".
	Key     string `json:"key"`
	Kind    string `json:"kind"`
	Name    string `json:"name,omitempty"`
	Address string `json:"address,omitempty"`
}

// grant is a single (action, resource) pair from an IAM statement, or an
// attached policy whose contents kam cannot see (opaque).
type grant struct {
	effect       string
	action       string
	notActions   []string
	resource     string
	notResources []string
	condition    string
	via          string // where the grant comes from, for humans
	opaque       bool
	label        string // what was attached, for opaque grants
}

func (g grant) actionLabel() string {
	if g.opaque {
		return "?"
	}
	if len(g.notActions) > 0 {
		return "everything except " + strings.Join(g.notActions, ", ")
	}
	return g.action
}

func (g grant) resourceLabel() string {
	if g.opaque {
		return "?"
	}
	if len(g.notResources) > 0 {
		return "everything except " + strings.Join(g.notResources, ", ")
	}
	return g.resource
}

// trustEntry is one principal allowed to assume a role.
type trustEntry struct {
	typ       string // AWS, Service, Federated, CanonicalUser
	value     string
	condition string
	stmt      policy.Statement
	via       string
}

func (t trustEntry) key() string { return t.typ + "|" + t.value + "|" + t.condition }

type principalState struct {
	Principal
	defined bool // an aws_iam_role/user/group resource exists on this side
	grants  []grant
	trust   []trustEntry
}

type side int

const (
	before side = iota
	after
)

type policyInfo struct {
	name, address string
	doc           *policy.Document // nil when the document is known only after apply
}

// state is every principal's IAM access on one side of the plan.
type state struct {
	plan         *tfplan.Plan
	side         side
	principals   map[string]*principalState
	byAddress    map[string]string // aws_iam_role/user/group address -> principal key
	policyByARN  map[string]*policyInfo
	policyByAddr map[string]*policyInfo
	members      map[string][]string // group key -> user keys
	warnings     map[string]bool
}

func build(p *tfplan.Plan, sd side) *state {
	s := &state{
		plan:         p,
		side:         sd,
		principals:   map[string]*principalState{},
		byAddress:    map[string]string{},
		policyByARN:  map[string]*policyInfo{},
		policyByAddr: map[string]*policyInfo{},
		members:      map[string][]string{},
		warnings:     map[string]bool{},
	}

	// Pass 1: identities and customer managed policies, so pass 2 can
	// resolve references to them.
	for i := range p.ResourceChanges {
		rc := &p.ResourceChanges[i]
		v := s.values(rc)
		if v == nil {
			continue
		}
		switch rc.Type {
		case "aws_iam_role", "aws_iam_user", "aws_iam_group":
			name, _ := tfplan.Str(v, "name")
			ps := s.principal(strings.TrimPrefix(rc.Type, "aws_iam_"), name, rc.Address)
			ps.defined = true
			ps.Address = rc.Address
			s.byAddress[rc.Address] = ps.Key
		case "aws_iam_policy":
			pi := &policyInfo{address: rc.Address}
			pi.name, _ = tfplan.Str(v, "name")
			if raw, ok := tfplan.Str(v, "policy"); ok {
				if doc, err := policy.Parse(raw); err == nil {
					pi.doc = &doc
				} else {
					s.warn("%s: %v", rc.Address, err)
				}
			}
			s.policyByAddr[rc.Address] = pi
			if arn, ok := tfplan.Str(v, "arn"); ok {
				s.policyByARN[arn] = pi
			}
		}
	}

	// Pass 2: everything that grants or links access.
	for i := range p.ResourceChanges {
		rc := &p.ResourceChanges[i]
		v := s.values(rc)
		if v == nil {
			continue
		}
		switch rc.Type {
		case "aws_iam_role":
			ps := s.principals[s.byAddress[rc.Address]]
			if raw, ok := tfplan.Str(v, "assume_role_policy"); ok {
				s.addTrust(ps, raw, "trust policy of "+rc.Address)
			}
			for _, ip := range tfplan.Blocks(v, "inline_policy") {
				name, _ := tfplan.Str(ip, "name")
				if raw, ok := tfplan.Str(ip, "policy"); ok {
					s.addDocument(ps, raw, fmt.Sprintf("inline policy %q in %s", name, rc.Address))
				}
			}
			for _, arn := range tfplan.StrList(v, "managed_policy_arns") {
				s.attachARN(ps, arn, "managed_policy_arns of "+rc.Address)
			}

		case "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy":
			kind := strings.TrimSuffix(strings.TrimPrefix(rc.Type, "aws_iam_"), "_policy")
			ps := s.resolvePrincipal(rc, v, kind)
			name, _ := tfplan.Str(v, "name")
			via := fmt.Sprintf("inline policy %q (%s)", name, rc.Address)
			if raw, ok := tfplan.Str(v, "policy"); ok {
				s.addDocument(ps, raw, via)
			} else {
				s.addOpaque(ps, via, "document known only after apply")
			}

		case "aws_iam_role_policy_attachment", "aws_iam_user_policy_attachment", "aws_iam_group_policy_attachment":
			kind := strings.TrimSuffix(strings.TrimPrefix(rc.Type, "aws_iam_"), "_policy_attachment")
			s.attach(s.resolvePrincipal(rc, v, kind), rc, v)

		case "aws_iam_policy_attachment":
			for _, kind := range []string{"role", "user", "group"} {
				for _, name := range tfplan.StrList(v, kind+"s") {
					s.attach(s.principal(kind, normalizeName(name), ""), rc, v)
				}
			}

		case "aws_iam_user_group_membership":
			user := s.resolvePrincipal(rc, v, "user")
			for _, g := range tfplan.StrList(v, "groups") {
				gk := s.principal("group", normalizeName(g), "").Key
				s.members[gk] = append(s.members[gk], user.Key)
			}

		case "aws_iam_group_membership":
			group := s.resolvePrincipal(rc, v, "group")
			for _, u := range tfplan.StrList(v, "users") {
				s.members[group.Key] = append(s.members[group.Key], s.principal("user", normalizeName(u), "").Key)
			}
		}
	}

	// Pass 3: users inherit the access of their groups.
	groupKeys := make([]string, 0, len(s.members))
	for gk := range s.members {
		groupKeys = append(groupKeys, gk)
	}
	sort.Strings(groupKeys)
	for _, gk := range groupKeys {
		group := s.principals[gk]
		for _, uk := range s.members[gk] {
			user := s.principals[uk]
			for _, g := range group.grants {
				g.via = "via " + gk + ": " + g.via
				user.grants = append(user.grants, g)
			}
		}
	}
	return s
}

func (s *state) values(rc *tfplan.ResourceChange) map[string]any {
	if rc.Mode != "managed" || !strings.HasPrefix(rc.Type, "aws_iam_") {
		return nil
	}
	if s.side == before {
		return rc.Change.Before
	}
	return rc.Change.After
}

func (s *state) warn(format string, args ...any) {
	s.warnings[fmt.Sprintf(format, args...)] = true
}

func (s *state) principal(kind, name, address string) *principalState {
	key := kind + "/" + name
	if name == "" {
		key = fmt.Sprintf("%s/<%s>", kind, address)
	}
	ps, ok := s.principals[key]
	if !ok {
		ps = &principalState{Principal: Principal{Key: key, Kind: kind, Name: name}}
		s.principals[key] = ps
	}
	return ps
}

// resolvePrincipal finds the role, user or group that attribute kind of rc
// points at. Values unknown until apply are resolved through configuration
// references, e.g. role = aws_iam_role.app.id.
func (s *state) resolvePrincipal(rc *tfplan.ResourceChange, v map[string]any, kind string) *principalState {
	if name, ok := tfplan.Str(v, kind); ok {
		return s.principal(kind, normalizeName(name), "")
	}
	if s.side == after {
		if ref, ok := s.plan.ResolveRef(rc, kind, "aws_iam_"+kind); ok {
			if key, ok := s.byAddress[ref.Address]; ok {
				return s.principals[key]
			}
		}
	}
	s.warn("%s: could not tell which %s it applies to", rc.Address, kind)
	return s.principal(kind, "", rc.Address)
}

func (s *state) attach(ps *principalState, rc *tfplan.ResourceChange, v map[string]any) {
	via := "attached by " + rc.Address
	if arn, ok := tfplan.Str(v, "policy_arn"); ok {
		s.attachARN(ps, arn, via)
		return
	}
	if s.side == after {
		if ref, ok := s.plan.ResolveRef(rc, "policy_arn", "aws_iam_policy"); ok {
			if pi := s.policyByAddr[ref.Address]; pi != nil {
				s.addPolicy(ps, pi, via)
				return
			}
		}
	}
	s.addOpaque(ps, via, "policy known only after apply")
}

func (s *state) attachARN(ps *principalState, arn, via string) {
	if pi := s.policyByARN[arn]; pi != nil {
		s.addPolicy(ps, pi, via)
		return
	}
	if name, doc, ok := policy.Managed(arn); ok {
		s.addStatements(ps, doc, fmt.Sprintf("AWS managed %s, %s", name, via))
		return
	}
	label := arn
	if policy.IsAWSManaged(arn) {
		label = "AWS managed " + arn[strings.LastIndex(arn, "/")+1:]
	}
	s.addOpaque(ps, via, label)
}

func (s *state) addPolicy(ps *principalState, pi *policyInfo, via string) {
	label := "policy/" + pi.name + " (" + pi.address + ")"
	if pi.name == "" {
		label = pi.address
	}
	if pi.doc == nil {
		s.addOpaque(ps, via, label+", document known only after apply")
		return
	}
	s.addStatements(ps, *pi.doc, label+", "+via)
}

func (s *state) addDocument(ps *principalState, raw, via string) {
	doc, err := policy.Parse(raw)
	if err != nil {
		s.warn("%s: %v", via, err)
		return
	}
	s.addStatements(ps, doc, via)
}

func (s *state) addStatements(ps *principalState, doc policy.Document, via string) {
	for _, st := range doc.Statements {
		ps.grants = append(ps.grants, expand(st, via)...)
	}
}

func (s *state) addOpaque(ps *principalState, via, label string) {
	ps.grants = append(ps.grants, grant{effect: "Allow", opaque: true, label: label, via: via})
}

func (s *state) addTrust(ps *principalState, raw, via string) {
	doc, err := policy.Parse(raw)
	if err != nil {
		s.warn("%s: %v", via, err)
		return
	}
	for _, st := range doc.Statements {
		if st.Effect != "Allow" || !allowsAssume(st) {
			continue
		}
		cond := st.ConditionKey()
		for typ, vals := range st.Principals {
			for _, val := range vals {
				ps.trust = append(ps.trust, trustEntry{typ: typ, value: val, condition: cond, stmt: st, via: via})
			}
		}
	}
}

func allowsAssume(st policy.Statement) bool {
	for _, a := range st.Actions {
		if policy.MatchAction(a, "sts:AssumeRole") || policy.MatchAction(a, "sts:AssumeRoleWithWebIdentity") ||
			policy.MatchAction(a, "sts:AssumeRoleWithSAML") {
			return true
		}
	}
	return false
}

// expand turns a statement into one grant per (action, resource) pair, so
// the diff can tell exactly which pairs are new.
func expand(st policy.Statement, via string) []grant {
	base := grant{effect: st.Effect, condition: st.ConditionKey(), via: via}
	resources := st.Resources
	if len(st.NotResources) > 0 {
		base.notResources = sortedCopy(st.NotResources)
		resources = []string{""}
	}
	var out []grant
	for _, r := range resources {
		if len(st.NotActions) > 0 {
			g := base
			g.notActions, g.resource = sortedCopy(st.NotActions), r
			out = append(out, g)
			continue
		}
		for _, a := range st.Actions {
			g := base
			g.action, g.resource = a, r
			out = append(out, g)
		}
	}
	return out
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

// normalizeName turns "arn:aws:iam::123:role/path/name" into "name".
func normalizeName(n string) string {
	if strings.HasPrefix(n, "arn:") {
		return n[strings.LastIndex(n, "/")+1:]
	}
	return n
}
