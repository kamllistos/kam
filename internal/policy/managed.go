package policy

import "strings"

// managedPolicies is a small catalog of AWS managed policies that matter most
// for access reviews. AWS updates these documents over time, so treat them as
// snapshots; anything not listed is reported as an attachment kam cannot see into.
var managedPolicies = map[string]string{
	"AdministratorAccess": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`,

	"PowerUserAccess": `{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","NotAction":["iam:*","organizations:*","account:*"],"Resource":"*"},
		{"Effect":"Allow","Action":["account:GetAccountInformation","account:GetPrimaryEmail","account:ListRegions",
			"iam:CreateServiceLinkedRole","iam:DeleteServiceLinkedRole","iam:ListRoles","organizations:DescribeOrganization"],"Resource":"*"}]}`,

	"IAMFullAccess": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:*",
		"organizations:DescribeAccount","organizations:DescribeOrganization","organizations:DescribeOrganizationalUnit",
		"organizations:DescribePolicy","organizations:ListChildren","organizations:ListParents",
		"organizations:ListPoliciesForTarget","organizations:ListRoots","organizations:ListPolicies",
		"organizations:ListTargetsForPolicy"],"Resource":"*"}]}`,

	"AmazonS3FullAccess": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:*","s3-object-lambda:*"],"Resource":"*"}]}`,

	"AmazonS3ReadOnlyAccess": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:Get*","s3:List*","s3:Describe*",
		"s3-object-lambda:Get*","s3-object-lambda:List*"],"Resource":"*"}]}`,
}

// Managed returns the catalogued document for an AWS managed policy ARN such
// as arn:aws:iam::aws:policy/AdministratorAccess.
func Managed(arn string) (name string, doc Document, ok bool) {
	if !IsAWSManaged(arn) {
		return "", Document{}, false
	}
	name = arn[strings.LastIndex(arn, "/")+1:]
	raw, ok := managedPolicies[name]
	if !ok {
		return name, Document{}, false
	}
	doc, err := Parse(raw)
	if err != nil {
		panic("policy: bad catalog entry " + name + ": " + err.Error())
	}
	return name, doc, true
}

// IsAWSManaged reports whether arn names an AWS managed policy in any partition.
func IsAWSManaged(arn string) bool {
	return strings.HasPrefix(arn, "arn:") && strings.Contains(arn, ":iam::aws:policy/")
}
