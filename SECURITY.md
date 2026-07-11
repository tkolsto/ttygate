# Security Policy

ttygate is a browser terminal gateway. A vulnerability can become command execution, credential exposure, or access to terminal contents, so suspected vulnerabilities must be handled privately.

## Report a vulnerability privately

Use [GitHub private vulnerability reporting](https://github.com/tkolsto/ttygate/security/advisories/new) for suspected vulnerabilities in ttygate.

Do not disclose a suspected vulnerability in a public issue, discussion, pull request, commit message, or other public channel. If GitHub private reporting is unavailable to you, open a public issue containing only a request for a private contact method—do not include technical details, logs, proof-of-concept material, or affected endpoints.

A useful private report includes:

- the affected version, commit, or branch;
- the environment and configuration needed to reproduce the behavior;
- minimal reproduction steps or proof of concept;
- the expected and observed behavior;
- an assessment of impact and likely attack prerequisites;
- a suggested mitigation, if you have one; and
- a safe way to contact you and whether you want public credit.

Remove credentials, terminal contents, session cookies, tickets, private keys, personal data, and unrelated secrets. Test only systems you own or are explicitly authorized to test. Do not disrupt services, access other people's data, or retain data beyond what is necessary to demonstrate the issue.

## What to expect

Maintainers will acknowledge the report when practical, assess its scope and severity, and coordinate remediation and disclosure through the private advisory. We may ask for clarification or a safe retest. If an advisory is warranted, we will coordinate publication and credit reporters who consent to being named.

This volunteer pre-release project has no response-time guarantee. Please keep the report private while assessment and remediation are in progress; if coordination stalls, state your intended disclosure timeline in the private advisory so the parties can plan safely.

## Supported versions

ttygate has no released versions yet.

| Version | Supported |
|---|---|
| Latest revision on `main` | Yes, during pre-release development |
| Older commits, development branches, and forks | No |
| Published releases | None exist |

Security fixes during pre-release development target the latest `main`. Once releases exist, this table will be replaced with an explicit supported-release policy. Fork maintainers and downstream distributors are responsible for their own support and disclosure processes.

## Scope

Reports about ttygate's code, build and release automation, documented deployment model, or first-party dependencies are in scope. The [threat model](docs/threat-model.md) describes the intended security boundaries and known residual risks.

Findings that only reproduce a documented residual risk may not require a code change, but private reports that reveal a practical escalation beyond the documented boundary are welcome. Social engineering, denial-of-service testing against shared infrastructure, physical attacks, and testing third-party systems without authorization are out of scope.
