# GitHub Actions workflows

| Workflow | Runs on | Secrets | What it does |
|---|---|---|---|
| `tests.yml` | push, pull request, manual | none | Runs the unit tests (`pytest`). |
| `semgrep.yml` | push, pull request, manual | none | Semgrep with the rules in `.semgrep/` (tests excluded). |
| `sonar.yml` | push, pull request, manual | `SONAR_TOKEN` | Runs the tests with coverage, then SonarCloud analysis. Fails early with a clear message if `SONAR_TOKEN` is missing. |
| `gitleaks.yml` | push, manual | none | Gitleaks secret scan of the full history with `gitleaks/gitleaks.toml`; report uploaded as an artifact (non-blocking). |
| `dependencycheck.yml` | push, manual | none | OWASP Dependency-Check (SCA); HTML report uploaded as an artifact. |
| `pipeline.yml` | push to `main` and `branch-*`, `v*` tags, manual | `GHCR_KEY` | Builds the Docker image (amd64 + arm64) and pushes it to `ghcr.io`. |

## One-time setup

1. SonarCloud: in the organization `niscy-eudiw`, create the project with key
   `niscy-eudiw_eudi-srv-web-issuing-eudiw-py` (the workflow derives it as `<owner>_<repo>`).
   Under Administration > Analysis Method, turn **Automatic Analysis off**:
   the workflow runs a CI analysis with coverage, and SonarCloud rejects CI
   analyses while Automatic Analysis is on.
2. Repository secrets (Settings > Secrets and variables > Actions):
   - `SONAR_TOKEN`: a SonarCloud token (My Account > Security) for the project above.
   - `GHCR_KEY`: a GitHub token with `write:packages`, used by `pipeline.yml` to push the image to ghcr.io.

`tests.yml`, `semgrep.yml`, `gitleaks.yml`, `dependencycheck.yml` need no secrets. `GITHUB_TOKEN` is provided by GitHub automatically.
