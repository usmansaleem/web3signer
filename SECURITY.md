# Security Policy

This policy applies to the Web3Signer repository and supplements the
[Consensys-Incorporated organization security policy](https://github.com/Consensys-Incorporated/.github/blob/main/SECURITY.md).
Where the two differ, this document takes precedence for Web3Signer.

## Reporting a vulnerability

Report vulnerabilities privately. We prefer GitHub private vulnerability reporting:

- **GitHub private vulnerability reporting (preferred):** open the
  [Security tab](https://github.com/Consensys-Incorporated/web3signer/security/advisories)
  and select **Report a vulnerability**.
- **Email:** [web3signer-security-report@consensys.com](mailto:web3signer-security-report@consensys.com),
  if you cannot use GitHub.

Do not report security issues through public issues, pull requests, or discussions.

### What to include

- The Web3Signer version, tag, or commit you tested, and how it was deployed: Docker image or
  distribution archive, subcommand (`eth1` or `eth2`), and configuration flags.
- A description of the issue and its potential impact.
- Steps to reproduce, or a proof of concept.
- How we can reach you, and whether and how you would like to be credited.

## What to expect

- We acknowledge reports within **5 business days**.
- We keep you informed through triage and remediation.
- We agree a coordinated disclosure timeline with you, and move faster for issues being actively
  exploited.
- We credit reporters who wish to be named, in the published advisory.
- Confirmed security issues are published as GitHub Security Advisories, with a CVE for security
  issues as described under [Trust model and scope](#trust-model-and-scope). Hardening reports may
  be published as informational advisories without a CVE.

## Supported versions

Security fixes are provided for **the latest release only**. Please test against the latest
release before reporting.

## Trust model and scope

Web3Signer does not authenticate or authorize API requests. Access must be restricted at the
network layer (bind address, firewall rules, private networks, mutual TLS, or equivalent), and any
client that can reach an enabled interface is treated as trusted. Web3Signer must not be exposed
to untrusted networks. Please read the
[key best practices](https://docs.web3signer.consensys.com/get-started/key-best-practices)
before assessing impact.

### Security issues

We treat a report as a security issue when it breaks a protection that is meant to hold even for
a client that can reach the API, or when it remains exploitable in a deployment that follows the
restrictions above. For example:

- Disclosure of key material, keystore passwords, or credentials for key stores and cloud
  services.
- Slashing protection bypass: signing a slashable message while slashing protection is enabled.
- Signatures that do not match the request: a different key, different data, or a different chain.
- Path traversal or arbitrary file access through API requests or loaded key data.
- Bypass of TLS client authentication.
- Vulnerabilities in dependencies that are reachable in Web3Signer.

### Hardening

Reports whose only impact is something a client that can reach Web3Signer is already able to do
by design are treated as hardening, for example:

- Missing authentication or authorization on the HTTP interfaces.
- Resource exhaustion or denial of service by a client that can already reach those interfaces.
- Findings that depend on exposing Web3Signer to an untrusted network.

We welcome these reports and will usually fix worthwhile ones as normal improvements. We may
publish an informational advisory for them, but do not request a CVE. We assess severity in the
context of this deployment model, not by raw CVSS score alone.

If you are unsure whether something qualifies, report it privately and we will decide during
triage.

## Other notes

- Report vulnerabilities in third-party dependencies to their maintainers, unless Web3Signer's use
  of the dependency creates a distinct issue.
- This policy does not by itself establish a bug bounty program.
- For bugs without a security impact, use the
  [issue tracker](https://github.com/Consensys-Incorporated/web3signer/issues). For support
  questions, use [GitHub Discussions](https://github.com/Consensys-Incorporated/web3signer/discussions).
