// Package tfplan reads the JSON form of a Terraform plan
// (terraform show -json tfplan) and resolves references between resources.
package tfplan

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// Plan is the subset of Terraform's plan JSON that kam needs.
type Plan struct {
	FormatVersion    string           `json:"format_version"`
	TerraformVersion string           `json:"terraform_version"`
	ResourceChanges  []ResourceChange `json:"resource_changes"`
	Configuration    Configuration    `json:"configuration"`

	byAddress map[string]int
	byConfig  map[string][]int
	refs      map[string]map[string][]string // config address -> attribute -> referenced addresses
}

// ResourceChange is one entry of resource_changes.
type ResourceChange struct {
	Address string `json:"address"`
	Mode    string `json:"mode"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Change  Change `json:"change"`
}

// Change holds a resource's values before and after the plan is applied.
// Before is nil for creates and After is nil for deletes. Attributes that are
// only known after apply are absent from After.
type Change struct {
	Actions []string       `json:"actions"`
	Before  map[string]any `json:"before"`
	After   map[string]any `json:"after"`
}

// Configuration is the module tree with each attribute's references.
type Configuration struct {
	RootModule Module `json:"root_module"`
}

// Module is one module in the configuration tree.
type Module struct {
	Resources   []ConfigResource      `json:"resources"`
	ModuleCalls map[string]ModuleCall `json:"module_calls"`
}

// ModuleCall is a module block and the module it instantiates.
type ModuleCall struct {
	Module Module `json:"module"`
}

// ConfigResource is a resource block. Its address is relative to its module.
type ConfigResource struct {
	Address     string                     `json:"address"`
	Expressions map[string]json.RawMessage `json:"expressions"`
}

// Load decodes plan JSON and indexes it for reference lookups.
func Load(r io.Reader) (*Plan, error) {
	var p Plan
	if err := json.NewDecoder(r).Decode(&p); err != nil {
		return nil, fmt.Errorf("read plan JSON: %w", err)
	}
	if p.FormatVersion == "" {
		return nil, errors.New("input is not Terraform plan JSON (no format_version); create it with: terraform show -json tfplan > plan.json")
	}
	p.index()
	return &p, nil
}

func (p *Plan) index() {
	p.byAddress = make(map[string]int, len(p.ResourceChanges))
	p.byConfig = make(map[string][]int, len(p.ResourceChanges))
	for i, rc := range p.ResourceChanges {
		p.byAddress[rc.Address] = i
		ca := StripIndex(rc.Address)
		p.byConfig[ca] = append(p.byConfig[ca], i)
	}
	p.refs = map[string]map[string][]string{}
	p.walk(p.Configuration.RootModule, "")
}

func (p *Plan) walk(m Module, prefix string) {
	for _, res := range m.Resources {
		addr := join(prefix, res.Address)
		for attr, raw := range res.Expressions {
			var e struct {
				References []string `json:"references"`
			}
			// Nested blocks are arrays and fail to decode here; kam only needs
			// top-level attribute references.
			if json.Unmarshal(raw, &e) != nil || len(e.References) == 0 {
				continue
			}
			if p.refs[addr] == nil {
				p.refs[addr] = map[string][]string{}
			}
			for _, ref := range e.References {
				p.refs[addr][attr] = append(p.refs[addr][attr], join(prefix, ref))
			}
		}
	}
	for name, call := range m.ModuleCalls {
		p.walk(call.Module, join(prefix, "module."+name))
	}
}

// ResolveRef finds the resource of type wantType that attribute attr of rc
// refers to in the configuration, such as the aws_iam_role behind
// role = aws_iam_role.app.name. It is how kam follows values that are only
// known after apply.
func (p *Plan) ResolveRef(rc *ResourceChange, attr, wantType string) (*ResourceChange, bool) {
	for _, ref := range p.refs[StripIndex(rc.Address)][attr] {
		// Drop trailing attribute names until the reference names a resource.
		for cand := ref; cand != ""; {
			if i, ok := p.byAddress[cand]; ok && p.ResourceChanges[i].Type == wantType {
				return &p.ResourceChanges[i], true
			}
			if idx := p.byConfig[StripIndex(cand)]; len(idx) == 1 && p.ResourceChanges[idx[0]].Type == wantType {
				return &p.ResourceChanges[idx[0]], true
			}
			j := strings.LastIndex(cand, ".")
			if j < 0 {
				break
			}
			cand = cand[:j]
		}
	}
	return nil, false
}

var instanceKey = regexp.MustCompile(`\[[^\]]*\]`)

// StripIndex removes count and for_each instance keys from an address.
func StripIndex(addr string) string {
	return instanceKey.ReplaceAllString(addr, "")
}

func join(prefix, s string) string {
	if prefix == "" {
		return s
	}
	return prefix + "." + s
}

// Str returns a non-empty, known string attribute.
func Str(v map[string]any, key string) (string, bool) {
	s, ok := v[key].(string)
	return s, ok && s != ""
}

// StrList returns the known string elements of a list or set attribute.
func StrList(v map[string]any, key string) []string {
	items, _ := v[key].([]any)
	out := make([]string, 0, len(items))
	for _, it := range items {
		if s, ok := it.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}

// Blocks returns the elements of a nested block attribute.
func Blocks(v map[string]any, key string) []map[string]any {
	items, _ := v[key].([]any)
	out := make([]map[string]any, 0, len(items))
	for _, it := range items {
		if m, ok := it.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}
