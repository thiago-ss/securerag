# Security Policy

## Reporting a vulnerability

This project takes tenant isolation seriously. If you believe you have found a way for one tenant
to read, infer, cite, preview, stream, export, log, audit, or send to a model another tenant's
protected information, or any way for a principal to exceed their document grants, please report it
privately.

- Email: open a **private** security issue via GitHub (this repository's security advisories), or
  contact the maintainer directly.
- Do NOT file public issues for suspected security defects.
- Include: reproduction steps, the tenant/principal setup, the exact request(s), and the expected
  vs observed behavior.

## What to expect

- Acknowledgement within 5 business days.
- A fix lands with a regression test (the adversarial suite must gain a case for the finding) and
  an RC release; the evaluator report is updated.
- You are credited in the advisory unless you prefer otherwise.

## Scope

In scope: the application, its RLS policies, the retrieval/evidence/citation/refusal pipeline, the
audit trail, session handling, and the adversarial surface described in
`docs/threat-model.md`.

Out of scope (operational, not application): total compromise of the database superuser, KMS/root
encryption keys, host root, OIDC signing keys, or an approved model provider. These are mitigated
operationally (least privilege, secret management, egress controls, rotation, backups) — see
`docs/ops/`.

## Trust model summary

Authorization is enforced by deterministic identity, authorization, database, and output controls.
The LLM never decides authorization. A detector or provider failure never weakens tenant or ACL
enforcement.
