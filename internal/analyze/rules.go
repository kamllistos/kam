package analyze

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/kamllistos/kam/internal/policy"
)

// Actions that let an identity grant itself or others more access.
var escalationActions = []string{
	"iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion",
	"iam:AttachUserPolicy", "iam:AttachRolePolicy", "iam:AttachGroupPolicy",
	"iam:PutUserPolicy", "iam:PutRolePolicy", "iam:PutGroupPolicy",
	"iam:CreateAccessKey", "iam:CreateLoginProfile", "iam:UpdateLoginProfile",
	"iam:UpdateAssumeRolePolicy", "iam:AddUserToGroup",
	"iam:DeleteUserPermissionsBoundary", "iam:DeleteRolePermissionsBoundary",
}

// Actions that start compute running as a role passed with iam:PassRole.
var launchWithRole = []string{
	"ec2:RunInstances", "lambda:CreateFunction", "lambda:UpdateFunctionConfiguration",
	"ecs:RunTask", "ecs:RegisterTaskDefinition", "ecs:CreateService",
	"cloudformation:CreateStack", "cloudformation:UpdateStack",
	"glue:CreateDevEndpoint", "glue:CreateJob", "glue:UpdateJob",
	"sagemaker:CreateNotebookInstance", "sagemaker:CreateTrainingJob",
	"codebuild:CreateProject", "codebuild:UpdateProject",
	"datapipeline:CreatePipeline", "states:CreateStateMachine", "apprunner:CreateService",
}

// Actions that run code inside existing workloads, inheriting their roles.
var codeExecActions = []string{
	"lambda:UpdateFunctionCode", "ssm:SendCommand", "ssm:StartSession",
	"ec2-instance-connect:SendSSHPublicKey", "ecs:ExecuteCommand",
}

var defenseEvasionActions = []string{
	"cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "cloudtrail:UpdateTrail", "cloudtrail:PutEventSelectors",
	"guardduty:DeleteDetector", "guardduty:UpdateDetector", "guardduty:DisassociateFromMasterAccount",
	"config:StopConfigurationRecorder", "config:DeleteConfigurationRecorder",
	"securityhub:DisableSecurityHub", "logs:DeleteLogGroup", "organizations:LeaveOrganization",
}

var dataReadActions = []string{
	"secretsmanager:GetSecretValue", "ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath",
	"kms:Decrypt", "s3:GetObject", "dynamodb:Scan",
}

var destructiveActions = []string{
	"s3:DeleteBucket", "s3:DeleteObject", "ec2:TerminateInstances", "ec2:DeleteSnapshot",
	"rds:DeleteDBInstance", "rds:DeleteDBCluster", "dynamodb:DeleteTable",
	"kms:ScheduleKeyDeletion", "backup:DeleteRecoveryPoint",
}

type hit struct {
	rule   string
	sev    Severity
	title  string
	detail string
}

// classify returns every rule a newly granted permission triggers.
func classify(g grant) []hit {
	if g.opaque {
		sev := Low
		if strings.Contains(g.label, "FullAccess") || strings.Contains(g.label, "Admin") {
			sev = Medium
		}
		return []hit{{"opaque-policy", sev, "Attached policy kam cannot see into",
			"The policy document is not in the plan or in kam's managed-policy catalog, so review what it grants by hand."}}
	}
	broad := isBroad(g)

	if len(g.notActions) > 0 {
		if !excludes(g.notActions, "iam:PutRolePolicy") {
			return []hit{{"notaction-admin", Critical, "Administrator-equivalent access through NotAction",
				"An Allow with NotAction grants every action it does not list. IAM is not excluded, so it can grant itself anything."}}
		}
		sev := High
		if !broad {
			sev = Medium
		}
		return []hit{{"notaction-broad", sev, "Near-administrator access through NotAction",
			"An Allow with NotAction grants every AWS action except the listed ones, including services AWS adds later."}}
	}

	if g.action == "*" || g.action == "*:*" {
		if broad {
			return []hit{{"admin", Critical, "Full administrator access", "Allows every action on every resource."}}
		}
		return []hit{{"all-actions", High, "Every action on a resource", "Allows every action on the listed resource."}}
	}

	var hits []hit
	add := func(list []string, rule string, broadSev, narrowSev Severity, title, detail string) {
		if len(matching(g.action, list)) == 0 {
			return
		}
		sev := narrowSev
		if broad {
			sev = broadSev
		}
		if sev > Info {
			hits = append(hits, hit{rule, sev, title, detail})
		}
	}
	add(escalationActions, "privesc", Critical, High, "Privilege escalation through IAM",
		"Can write or attach IAM policies, mint credentials or rewrite trust, which lets it grant itself more access.")
	if policy.MatchAction(g.action, "iam:PassRole") && broad {
		hits = append(hits, hit{"passrole-broad", High, "Can pass any role to AWS services",
			"iam:PassRole on a wildcard lets it hand any role in the account to a service it controls."})
	}
	if policy.MatchAction(g.action, "sts:AssumeRole") && broad {
		hits = append(hits, hit{"assume-any", High, "Can assume any role that trusts this account",
			"sts:AssumeRole on a wildcard reaches every role whose trust policy allows this account."})
	}
	add(codeExecActions, "code-exec", High, Medium, "Can run code inside existing workloads",
		"Can change function code or run commands on instances and containers, inheriting their roles.")
	add(defenseEvasionActions, "defense-evasion", High, High, "Can switch off security logging or detection",
		"Can stop or delete CloudTrail, GuardDuty, Config, Security Hub or log groups.")
	add(dataReadActions, "data-read-broad", High, Info, "Can read secrets or data across the account",
		"Can read secrets, parameters, objects or decrypt with any key, not just the ones it needs.")
	add(destructiveActions, "destructive-broad", High, Info, "Can delete data or infrastructure account-wide",
		"Can delete buckets, databases, snapshots, instances or schedule KMS key deletion on any resource.")
	if len(hits) == 0 && strings.Contains(g.action, "*") && broad {
		hits = append(hits, hit{"wildcard-broad", Medium, "Wildcard actions on all resources",
			"A wildcard action on every resource is hard to reason about and grows as AWS adds actions."})
	}
	return hits
}

// baseSeverity is the severity of a new permission no rule cares about.
func baseSeverity(g grant) Severity {
	if isBroad(g) && !isReadOnly(g.action) {
		return Low
	}
	return Info
}

var readOnlyVerb = regexp.MustCompile(`(?i):(get|list|describe|head|view|search|lookup|batchget|query|select)`)

func isReadOnly(action string) bool { return readOnlyVerb.MatchString(action) }

func isBroad(g grant) bool {
	if len(g.notResources) > 0 {
		return true
	}
	return broadResource(g.resource)
}

// broadResource reports whether a resource pattern spans a whole account or
// resource type rather than named resources.
func broadResource(res string) bool {
	if res == "*" {
		return true
	}
	parts := strings.SplitN(res, ":", 6)
	if len(parts) < 6 {
		return strings.Contains(res, "*")
	}
	rp := parts[5]
	if rp == "*" || strings.HasPrefix(rp, "*") {
		return true
	}
	if parts[2] == "s3" { // s3 ARNs start with the bucket name, so bucket/* is one bucket
		return false
	}
	// A type-level wildcard such as role/*, secret:* or parameter/*.
	if i := strings.IndexAny(rp, "/:"); i > 0 && rp[i+1:] == "*" {
		return true
	}
	return false
}

func matching(pattern string, list []string) []string {
	var out []string
	for _, a := range list {
		if policy.MatchAction(pattern, a) {
			out = append(out, a)
		}
	}
	return out
}

func excludes(notActions []string, action string) bool {
	for _, na := range notActions {
		if policy.MatchAction(na, action) {
			return true
		}
	}
	return false
}

// allowsAction reports whether g allows a concrete action.
func allowsAction(g grant, action string) bool {
	if g.opaque || g.effect != "Allow" {
		return false
	}
	if len(g.notActions) > 0 {
		return !excludes(g.notActions, action)
	}
	return policy.MatchAction(g.action, action)
}

var githubOIDC = "token.actions.githubusercontent.com"

// classifyTrust scores a principal newly allowed to assume a role.
func classifyTrust(t trustEntry, ownAccounts []string) hit {
	switch {
	case t.value == "*":
		if t.condition == "" {
			return hit{"public-trust", Critical, "Anyone with an AWS account can assume this role",
				"The trust policy allows Principal \"*\" with no conditions."}
		}
		return hit{"public-trust-conditional", High, "Any AWS principal can assume this role if conditions match",
			"The trust policy allows Principal \"*\"; only its Condition block stands between this role and the internet."}

	case t.typ == "Federated" && strings.Contains(t.value, githubOIDC):
		subs, ok := t.stmt.ConditionValues(githubOIDC + ":sub")
		if !ok {
			return hit{"github-oidc-unscoped", Critical, "Any GitHub repository can assume this role",
				"The GitHub Actions OIDC trust has no " + githubOIDC + ":sub condition, so a workflow in anyone's repository can get these credentials."}
		}
		for _, sub := range subs {
			if sub == "*" || strings.HasPrefix(sub, "repo:*") {
				return hit{"github-oidc-unscoped", Critical, "Any GitHub repository can assume this role",
					fmt.Sprintf("The %s:sub condition %q matches every repository on GitHub.", githubOIDC, sub)}
			}
		}
		for _, sub := range subs {
			if strings.Contains(sub, "*") {
				return hit{"github-oidc-wildcard", Medium, "GitHub OIDC trust uses a wildcard subject",
					fmt.Sprintf("The subject %q allows every branch, tag or environment it matches, including pull requests.", sub)}
			}
		}
		return hit{"github-oidc", Info, "GitHub Actions can assume this role", "Scoped to: " + strings.Join(subs, ", ")}

	case t.typ == "AWS":
		acct := accountOf(t.value)
		if acct == "" {
			return hit{"aws-trust", Info, "New AWS principal can assume this role", ""}
		}
		if len(ownAccounts) == 0 {
			return hit{"cross-account-trust", Medium, "Account " + acct + " can assume this role",
				"Pass --account with your own account IDs so kam can tell internal trust from external."}
		}
		for _, own := range ownAccounts {
			if own == acct {
				return hit{"internal-trust", Info, "Another principal in your accounts can assume this role", ""}
			}
		}
		detail := "Principals in an account you did not list with --account can get these credentials."
		if _, ok := t.stmt.ConditionValues("sts:ExternalId"); !ok {
			detail += " There is no sts:ExternalId condition, so a confused-deputy attack is possible if it is a vendor."
		}
		return hit{"external-trust", High, "External account " + acct + " can assume this role", detail}

	case t.typ == "Service":
		return hit{"service-trust", Info, "AWS service can assume this role", ""}
	default:
		return hit{"federated-trust", Low, "New federated identity can assume this role",
			"Check the identity provider and the conditions that limit which users it admits."}
	}
}

var accountID = regexp.MustCompile(`^\d{12}$`)

func accountOf(v string) string {
	if accountID.MatchString(v) {
		return v
	}
	if parts := strings.Split(v, ":"); len(parts) >= 5 && strings.HasPrefix(v, "arn:") && accountID.MatchString(parts[4]) {
		return parts[4]
	}
	return ""
}
