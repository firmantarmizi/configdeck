# Security Policy

## Supported versions

Until ConfigDeck reaches a stable 1.0 release, security fixes are provided for the latest release only. Deployments should use an immutable image digest and stay current with release notes.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting feature from the repository **Security** tab. Do not open a public issue for a suspected vulnerability.

Include:

- the affected version or image digest;
- a concise reproduction using synthetic data;
- the expected and observed security boundary;
- any known impact and suggested mitigation.

Never include real configuration values, passwords, TOTP seeds or codes, cookies, session tokens, KEKs, DEKs, ciphertext databases, backup files, or production host details.

## Security model

ConfigDeck is intended for private/internal access behind HTTPS and a private or identity-aware access layer. Review `docs/security-model.md`, `docs/deployment.md`, and `docs/operations.md` before production use.

Security reports will be assessed before public disclosure. A coordinated advisory and patched release should be prepared before exploit details are published.
