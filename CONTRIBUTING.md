# Contributing

Thanks for helping improve **Parrot Forensic Imager**. This project targets forensic-grade acquisition workflows, so changes are reviewed with an emphasis on correctness, auditability, and safety.

## Ground Rules

- **Do not weaken forensic safety defaults.**
  - Source evidence must remain read-only.
  - Any operation that can write to a device must be explicit, gated, and clearly documented.
- **Prefer deterministic, testable behavior** over convenience.
- **Log and audit**: user-facing actions should have clear audit entries where appropriate.

## Development Setup

Build the C core:

```bash
make clean
make core
```

Run tests:

```bash
PYTHONPATH=src python3 -m pytest -q
```

Run CLI locally:

```bash
PYTHONPATH=src python3 -m forensic_imager.cli --help
```

## Coding Guidelines

- Keep Python code compatible with the supported Python version noted in `pyproject.toml`.
- Avoid adding heavy dependencies unless there is a clear forensic/workflow need.
- Prefer small, modular modules in `src/forensic_imager/` and keep the C core focused on acquisition I/O + hashing.
- Any change impacting evidence integrity should include:
  - a clear rationale in the PR description
  - new/updated tests
  - updates to `README.md` if it changes operator behavior

## Submitting Changes

1. Create a feature branch.
2. Ensure `make core` and the full test suite pass.
3. Open a PR describing:
   - what changed
   - why it changed
   - how it was tested (include commands and environment)

## Reporting Bugs

When filing an issue, include:

- OS and version (Parrot/Debian base)
- Python version (`python3 -V`)
- command you ran
- relevant logs (`audit.jsonl`, `core_audit.jsonl`) and error output
- whether the source was a file or block device

## Security Issues

If you believe you found a security vulnerability (e.g., privilege escalation, unsafe device writes), do not open a public issue. Share details privately with the maintainer first.

