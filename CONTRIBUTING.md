# Contributing to SpecterKeys

SpecterKeys is a restricted internal security tool. Contributions are limited to members of the security engineering team.

## Development Setup

```bash
git clone https://github.com/specterkeys/specterkeys.git
cd specterkeys
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
```

## Running Tests

```bash
pytest tests/ -v --cov=src
```

## Running the Linter

```bash
flake8 src/ tests/
```

## Running the Security Scanner

```bash
bandit -r src/ -ll
```

## Pull Request Guidelines

- All PRs require review from at least one senior security engineer
- All tests must pass in CI before merge
- New honey file types require a matching renderer and unit test
- Do not add logging that could expose key material
- Do not add features that store plaintext secrets outside Secrets Manager

## Branch Naming

| Type | Pattern | Example |
|---|---|---|
| Feature | `feat/short-description` | `feat/azure-honey-keys` |
| Fix | `fix/short-description` | `fix/alarm-filter-pattern` |
| Docs | `docs/short-description` | `docs/ir-playbook` |
