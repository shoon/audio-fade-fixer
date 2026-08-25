# Security Policy

## Supported versions

Security fixes are applied to the latest release line.

| Version | Supported |
| --- | --- |
| 0.1.x | Yes |
| Older versions | No |

## Report a vulnerability

Do not open a public issue for a suspected vulnerability. Use [GitHub private vulnerability reporting](https://github.com/shoon/audio-fade-fixer/security/advisories/new) instead.

Include:

- the affected version and Windows version;
- a clear description of the impact;
- steps to reproduce in a test environment;
- any proof of concept that does not contain credentials or personal data;
- whether the issue can write outside the documented registry targets or cross the UAC boundary.

You should receive an acknowledgement within seven days. Please allow time to investigate and prepare a safe release before public disclosure.

## Scope

High-priority reports include arbitrary registry writes, unsafe restore-file parsing, path or reparse-point bypasses, privilege-boundary errors, backup tampering that passes validation, and unintended command execution.

General Realtek driver behavior, the effectiveness of the workaround on a particular computer, and Windows SmartScreen reputation are not security vulnerabilities in this project.
