# Security scope and acceptable use

SealedCodeBounty is an **authorized security-challenge platform**. It evaluates
submissions only against isolated challenge environments deliberately supplied
by their owner. It is not a scanner, remote exploitation service, malware
platform, or tool for targeting third-party systems.

## Permitted use

- Intentionally vulnerable CTF-style challenges and training environments.
- Software owned by the bounty creator or covered by explicit written testing
  authorization.
- Synthetic secrets and flags generated specifically for challenge judging.
- Defensive research conducted within the published challenge scope.

## Prohibited use

- Targets the creator does not own or lack permission to test.
- Public IP addresses, production systems, or infrastructure outside the
  uploaded challenge environment.
- Credential theft, phishing, persistence, destructive payloads, botnets,
  malware delivery, denial of service, or evasion of security controls.
- Attempts to escape the judge, access its host, contact external systems, or
  obtain another user's submission or secret.
- Uploading personal data, production credentials, or real-world secrets.

## Platform controls

The intended production verifier:

- runs only a target supplied for the specific bounty;
- gives the submission no Internet access and only the isolated target hostname;
- applies CPU, memory, process, output, archive, and wall-clock limits;
- encrypts submissions to an attested enclave key before upload;
- logs only identifiers, outcomes, and redacted diagnostics;
- releases a successful submission only to the bounty creator's encryption key;
- rejects malformed, oversized, unauthorized, or out-of-scope requests.

Target ownership is not established merely by checking a box. A hosted service
must retain the creator's attestation, establish an abuse-reporting channel, and
support suspension and evidence preservation. Higher-risk or ambiguous targets
require manual review before activation.

## Current development status

This repository is pre-production. `enclave-exec/` is a local Docker prototype,
not an AWS Nitro Enclave, and must bind to loopback only. Building an uploaded
Dockerfile executes untrusted build instructions; it is disabled unless the
operator explicitly sets `SCB_ALLOW_UNTRUSTED_TARGET_BUILDS=1` in a disposable,
network-restricted development environment. Do not expose that service to the
Internet or accept real submissions until the enclave, attestation, KMS policy,
parent proxy, and production sandbox have passed review.

Report suspected abuse or a security issue privately to the repository owner.
Do not include exploit payloads, credentials, or personal data in a public issue.

