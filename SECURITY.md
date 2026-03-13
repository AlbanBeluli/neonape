# Security Policy

## Reporting

If you discover a security issue in Neon Ape, please do not open a public issue with exploit details.

Open a GitHub security advisory or contact the maintainer privately first. Include:

- affected command or module
- impact summary
- reproduction steps
- any suggested remediation

## Project Security Goals

- local-only execution by default
- no HTTP service by default
- validated inputs for tool wrappers
- parameterized database writes
- minimal disclosure of local environment details in UI output

## Out of Scope

The repository may include references to third-party tools. Vulnerabilities in those upstream tools should be reported to their maintainers unless Neon Ape’s integration materially introduces the issue.
