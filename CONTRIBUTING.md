# Contributing to fastapi-security-headers

Thanks for your interest in improving `fastapi-security-headers`. This project
is a small, zero-dependency ASGI middleware, and it stays healthy because people
like you report bugs, add tests, and sharpen the docs. You do not need to be a
security expert to help.

This guide gives you the fastest path from a fresh clone to a merged pull
request.

## Quick path

1. Pick an issue labeled `good first issue` or `help wanted`.
2. Comment on the issue so it can be assigned to you.
3. Set up the project locally (see below).
4. Make one focused change, with tests and docs.
5. Open a pull request that links the issue with `Closes #`.

## What kinds of contributions are useful

| Contribution | Examples |
|--------------|----------|
| Code | New presets, config options, middleware behavior, bug fixes. |
| Tests | Covering an untested branch, reproducing a reported bug, adding edge cases. |
| Docs | Improving the README, adding usage examples, fixing unclear wording. |
| Examples | Small runnable snippets that show a real FastAPI integration. |
| Issue triage | Reproducing reports, confirming severity, asking for missing details. |

## Prerequisites

- Python 3.9 or newer.
- `git`.

## Local development setup

Run these commands exactly:

```bash
git clone https://github.com/aletgdev/fastapi-security-headers.git
cd fastapi-security-headers
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

The `dev` extra installs `pytest`, `pytest-asyncio`, `httpx`, `fastapi`,
`build`, `twine`, and `ruff`, which is everything you need to test, lint, and
build the package.

## Running the tests

```bash
pytest -v
```

CI runs the suite on Python 3.9 through 3.13, so keep your changes
compatible with the oldest supported version. Prefer standard-library
constructs over newer syntax that 3.9 cannot parse.

## Linting and formatting

This project uses [Ruff](https://docs.astral.sh/ruff/):

```bash
ruff check .
ruff format .
```

Run `ruff check .` before opening a pull request. Use `ruff format .` if you
want the same formatting CI expects.

## Project layout

```text
fastapi-security-headers/
├── src/
│   └── fastapi_security_headers/
│       ├── __init__.py     # public exports
│       ├── config.py       # SecurityHeadersConfig and related dataclasses
│       ├── middleware.py   # the pure-ASGI middleware
│       ├── presets.py      # Presets.default(), .api(), .strict(), .swagger_friendly()
│       └── py.typed        # marks the package as typed
├── tests/
│   ├── conftest.py         # shared fixtures
│   ├── test_config.py      # config behavior
│   ├── test_middleware.py  # middleware behavior
│   └── test_presets.py     # preset behavior
├── pyproject.toml
└── README.md
```

## Finding something to work on

Start with issues labeled
[`good first issue`](https://github.com/aletgdev/fastapi-security-headers/labels/good%20first%20issue)
or [`help wanted`](https://github.com/aletgdev/fastapi-security-headers/labels/help%20wanted).

Before you start coding, **comment on the issue** so a maintainer can assign it
to you. This avoids two people working on the same fix at the same time. If you
want to work on something that is not yet filed, open an issue first so the
approach can be discussed.

## Contribution workflow

1. Fork the repository.
2. Create a branch from `main` using a descriptive prefix:
   - `fix/...` for bug fixes
   - `feat/...` for new features
   - `docs/...` for documentation
3. Make your change and add or update tests.
4. Commit using [Conventional Commits](https://www.conventionalcommits.org/)
   (for example, `fix: respect route-level HSTS header`).
5. Push your branch to your fork.
6. Open a pull request and link the issue with `Closes #<issue-number>` in the
   description.

## Commit rules

- Use Conventional Commits (`fix:`, `feat:`, `docs:`, `test:`, `chore:`).
- Do **not** add a `Co-Authored-By` trailer or any AI-attribution trailer to
  your commits.

## Pull request checklist

- [ ] The PR contains one focused change.
- [ ] Tests are added or updated for the change.
- [ ] Documentation is updated when behavior or usage changes.
- [ ] `pytest` passes locally.
- [ ] The commit message follows Conventional Commits.

## Code of Conduct

By participating, you agree to follow our
[Code of Conduct](CODE_OF_CONDUCT.md). Please report unacceptable behavior to
the contact listed there.
