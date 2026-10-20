// Package policy parses AWS IAM policy documents and evaluates IAM wildcards.
package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// Statement is one IAM policy statement with every field normalised to lists.
type Statement struct {
	Sid          string
	Effect       string // "Allow" or "Deny"
	Actions      []string
	NotActions   []string
	Resources    []string
	NotResources []string
	// Principals maps a principal type (AWS, Service, Federated, CanonicalUser)
	// to its values. A bare "*" principal is stored as {"AWS": ["*"]}.
	Principals map[string][]string
	// Condition maps operator -> condition key -> values.
	Condition map[string]map[string][]string
}

// Document is a parsed IAM policy document.
type Document struct {
	Version    string
	Statements []Statement
}

// Parse parses an IAM policy document. Statement, Action, Resource and
// Principal may each be a single value or a list, as IAM allows.
func Parse(raw string) (Document, error) {
	var doc Document
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return doc, nil
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &top); err != nil {
		return doc, fmt.Errorf("parse policy document: %w", err)
	}
	if v, ok := top["Version"]; ok {
		_ = json.Unmarshal(v, &doc.Version)
	}
	st, ok := top["Statement"]
	if !ok {
		return doc, nil
	}
	var list []json.RawMessage
	if err := json.Unmarshal(st, &list); err != nil {
		list = []json.RawMessage{st}
	}
	for i, item := range list {
		s, err := parseStatement(item)
		if err != nil {
			return Document{}, fmt.Errorf("parse policy statement %d: %w", i, err)
		}
		doc.Statements = append(doc.Statements, s)
	}
	return doc, nil
}

// ConditionKey returns a canonical string for the statement's Condition
// block, or "" when it has none.
func (s Statement) ConditionKey() string {
	if len(s.Condition) == 0 {
		return ""
	}
	b, _ := json.Marshal(s.Condition) // map keys marshal in sorted order
	return string(b)
}

// ConditionValues returns every value tested against key under any
// operator. Condition keys are case-insensitive in IAM.
func (s Statement) ConditionValues(key string) ([]string, bool) {
	var out []string
	found := false
	for _, keys := range s.Condition {
		for k, vals := range keys {
			if strings.EqualFold(k, key) {
				found = true
				out = append(out, vals...)
			}
		}
	}
	return out, found
}

func parseStatement(raw json.RawMessage) (Statement, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return Statement{}, err
	}
	var s Statement
	if v, ok := m["Sid"]; ok {
		_ = json.Unmarshal(v, &s.Sid)
	}
	var effect string
	if err := json.Unmarshal(m["Effect"], &effect); err != nil {
		return Statement{}, fmt.Errorf("missing or invalid Effect")
	}
	switch {
	case strings.EqualFold(effect, "allow"):
		s.Effect = "Allow"
	case strings.EqualFold(effect, "deny"):
		s.Effect = "Deny"
	default:
		return Statement{}, fmt.Errorf("unknown Effect %q", effect)
	}

	var err error
	fields := map[string]*[]string{
		"Action":      &s.Actions,
		"NotAction":   &s.NotActions,
		"Resource":    &s.Resources,
		"NotResource": &s.NotResources,
	}
	for key, dst := range fields {
		if *dst, err = stringList(m[key]); err != nil {
			return Statement{}, fmt.Errorf("%s: %w", key, err)
		}
	}
	if s.Principals, err = parsePrincipal(m["Principal"]); err != nil {
		return Statement{}, fmt.Errorf("Principal: %w", err)
	}
	if s.Condition, err = parseCondition(m["Condition"]); err != nil {
		return Statement{}, fmt.Errorf("Condition: %w", err)
	}
	return s, nil
}

func parsePrincipal(raw json.RawMessage) (map[string][]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var star string
	if json.Unmarshal(raw, &star) == nil {
		return map[string][]string{"AWS": {star}}, nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	out := make(map[string][]string, len(m))
	for typ, v := range m {
		vals, err := stringList(v)
		if err != nil {
			return nil, err
		}
		out[typ] = vals
	}
	return out, nil
}

func parseCondition(raw json.RawMessage) (map[string]map[string][]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var m map[string]map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	out := make(map[string]map[string][]string, len(m))
	for op, keys := range m {
		out[op] = make(map[string][]string, len(keys))
		for k, v := range keys {
			vals, err := stringList(v)
			if err != nil {
				return nil, err
			}
			out[op][k] = vals
		}
	}
	return out, nil
}

// stringList decodes a JSON scalar or array into strings. Numbers keep their
// literal form so account IDs are not mangled into floats.
func stringList(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	switch t := v.(type) {
	case nil:
		return nil, nil
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			out = append(out, scalar(e))
		}
		return out, nil
	default:
		return []string{scalar(t)}, nil
	}
}

func scalar(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}
