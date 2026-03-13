# Contributing

## Workflow

1. Fork the repository or create a feature branch.
2. Make focused changes with clear commit messages.
3. Run the local checks before opening a pull request:

```bash
.venv/bin/pytest -q
.venv/bin/python -m compileall neon_ape
```

4. Update documentation when command behavior, install flow, or storage behavior changes.
5. Open a pull request with a concise summary, verification notes, and any remaining risks.

## Scope

- Keep Neon Ape local-only by default.
- Do not add remote listeners or exposed services without an explicit security design.
- Prefer safe wrappers and allowlisted command construction over arbitrary shell execution.
- Avoid adding offensive automation such as brute force or exploitation workflows.

## Coding Notes

- Add tests for new parser, repository, config, or CLI behavior.
- Keep UI output concise and operator-friendly.
- Be careful not to leak absolute local paths or secrets in docs, screenshots, or test fixtures.
