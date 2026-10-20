# Contributing to kam

Thanks for helping! kam gets better with every real Terraform plan it sees, so even
"kam missed this" or "kam flagged something harmless" reports are valuable.

## Ways to help

- **Report a wrong result.** Open a [wrong result issue](https://github.com/kamllistos/kam/issues/new?template=wrong_result.yml)
  with the IAM change that kam got wrong. Strip account IDs and names first.
- **Add a risk rule.** Rules live in [`internal/analyze/rules.go`](internal/analyze/rules.go). A new
  privilege-escalation path or dangerous action is usually a few lines plus a test.
- **Pick up an issue.** Look for [`good first issue`](https://github.com/kamllistos/kam/labels/good%20first%20issue)
  or [`help wanted`](https://github.com/kamllistos/kam/labels/help%20wanted).
- **Ask or propose** in [Discussions](https://github.com/kamllistos/kam/discussions) before starting
  something big, such as Azure or GCP support.

Found a security problem in kam itself? Don't open an issue; see [SECURITY.md](SECURITY.md).

## Development setup

You need Go (the version in `go.mod`). Terraform is only needed to run the examples.

```sh
git clone https://github.com/kamllistos/kam && cd kam
go test ./...
go run . diff testdata/plan.json
```

## Making a change

1. **Branch from `main`.** Name it after the kind of change:

   | Prefix | For |
   |---|---|
   | `feat/` | new behaviour, e.g. `feat/azure-rbac` |
   | `fix/` | a bug or wrong result, e.g. `fix/passrole-condition` |
   | `docs/` | documentation and examples |
   | `chore/` | CI, dependencies, tooling |

2. **Keep it small and tested.** Add or update a test in the package you touch. A new rule
   needs a test that triggers it and one that shows it does not over-trigger.
3. **Check locally:** `gofmt -l .` prints nothing, and `go vet ./...` and `go test ./...` pass.
4. **Open a pull request** to `main`. Write the title as a
   [Conventional Commit](https://www.conventionalcommits.org/), because it becomes the commit message
   when the PR is squash-merged:
   - `feat: detect iam:PassRole to SageMaker`
   - `fix: ignore Deny statements with NotResource`
   - `docs: add GitHub Actions example`

`main` is protected: every change, including the maintainer's, goes through a pull request,
and CI must pass on Linux and Windows before it can merge.

## How releases work

Maintainers tag `main` with a version such as `v0.2.0`. The release workflow then builds
binaries for every platform, publishes a GitHub release and updates the Homebrew tap.
kam follows [semantic versioning](https://semver.org/): `fix` changes bump the patch number,
`feat` changes bump the minor number, and breaking changes are called out in the release notes.

By contributing you agree that your work is released under the [MIT license](LICENSE) and that
you will follow the [code of conduct](CODE_OF_CONDUCT.md).
