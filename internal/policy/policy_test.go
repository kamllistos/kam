package policy

import "testing"

func TestMatchAction(t *testing.T) {
	tests := []struct {
		pattern, action string
		want            bool
	}{
		{"*", "s3:GetObject", true},
		{"s3:*", "s3:GetObject", true},
		{"S3:get*", "s3:GetObject", true},
		{"s3:Get?bject", "s3:GetObject", true},
		{"s3:Put*", "s3:GetObject", false},
		{"iam:*Policy", "iam:PutRolePolicy", true},
		{"iam:*Policy", "iam:PassRole", false},
	}
	for _, tt := range tests {
		if got := MatchAction(tt.pattern, tt.action); got != tt.want {
			t.Errorf("MatchAction(%q, %q) = %v, want %v", tt.pattern, tt.action, got, tt.want)
		}
	}
}

func TestCoversAction(t *testing.T) {
	tests := []struct {
		broad, narrow string
		want          bool
	}{
		{"s3:*", "s3:Get*", true},
		{"s3:Get*", "s3:GetObject", true},
		{"s3:GetObject", "s3:Get*", false},
		{"s3:Get?", "s3:Get*", false},
		{"s3:*Object", "s3:Get*", false},
		{"*", "*", true},
	}
	for _, tt := range tests {
		if got := CoversAction(tt.broad, tt.narrow); got != tt.want {
			t.Errorf("CoversAction(%q, %q) = %v, want %v", tt.broad, tt.narrow, got, tt.want)
		}
	}
}

func TestParseShapes(t *testing.T) {
	doc, err := Parse(`{"Statement":{"Effect":"allow","Action":"s3:GetObject","Resource":["a","b"],
		"Principal":"*","Condition":{"StringEquals":{"aws:PrincipalAccount":111122223333}}}}`)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Statements) != 1 {
		t.Fatalf("got %d statements, want 1", len(doc.Statements))
	}
	s := doc.Statements[0]
	if s.Effect != "Allow" || len(s.Actions) != 1 || len(s.Resources) != 2 {
		t.Errorf("unexpected statement %+v", s)
	}
	if got := s.Principals["AWS"]; len(got) != 1 || got[0] != "*" {
		t.Errorf("Principals = %v, want AWS:*", s.Principals)
	}
	if vals, ok := s.ConditionValues("AWS:PrincipalAccount"); !ok || vals[0] != "111122223333" {
		t.Errorf("ConditionValues = %v %v, want the account ID unmangled", vals, ok)
	}
}

func TestParseRejectsBadEffect(t *testing.T) {
	if _, err := Parse(`{"Statement":[{"Effect":"Maybe","Action":"*","Resource":"*"}]}`); err == nil {
		t.Error("expected an error for an unknown Effect")
	}
}

func TestManaged(t *testing.T) {
	name, doc, ok := Managed("arn:aws:iam::aws:policy/AdministratorAccess")
	if !ok || name != "AdministratorAccess" || doc.Statements[0].Actions[0] != "*" {
		t.Errorf("Managed(AdministratorAccess) = %q %+v %v", name, doc, ok)
	}
	if _, _, ok := Managed("arn:aws:iam::111122223333:policy/AdministratorAccess"); ok {
		t.Error("a customer policy named AdministratorAccess must not match the AWS catalog")
	}
}
