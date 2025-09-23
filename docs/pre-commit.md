# Pre-commit hooks

This repository uses pre-commit to enforce fast, pragmatic checks locally and in CI.

What runs

- Core hygiene: merge conflicts, large files, trailing whitespace, EOLs, JSON/TOML/YAML syntax
- Python: Ruff (lint, with simple autofixes), Black (format)
- Shell: shfmt (format), shellcheck (lint)
- Secrets: detect-secrets (guarded by a baseline)

Install locally

- pipx install pre-commit # or: pip install --user pre-commit
- pre-commit install

First run

- pre-commit run --all-files

Secrets baseline maintenance

- The baseline lives at .secrets.baseline
- To update after legitimate changes:
  - pipx install detect-secrets # or: pip install --user detect-secrets
  - detect-secrets scan --all-files \
    --exclude-files '(node_modules|vendor|dist|build|\\.venv|\\.tox|\\.mypy_cache|\\.ruff_cache|\\.git|\\.idea|\\.vscode|coverage|\\.pytest_cache|\\.terraform|target)/' \\
    > .secrets.baseline
- Review the diff before committing the updated baseline.

Notes

- Hooks are pinned to specific versions for reproducibility.
- CI runs the same suite via GitHub Actions (see `.github/workflows/ci.yml`).
