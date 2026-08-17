# ConfigDeck Roadmap

ConfigDeck keeps a deliberately small, security-focused scope. Roadmap entries describe direction, not release commitments.

## Near-term polish

- Refine the comparison workspace expand/collapse controls and cell disclosure without making hover the only interaction.
- Complete an EN/ID translation catalog and language selector while keeping English as the default.
- Continue light/dark, keyboard, screen-reader, responsive table, spacing, and typography review.
- Add release screenshots and a concise first-run guide after the visual system stabilizes.

## Operational improvements under consideration

- Document additional reverse-proxy examples without coupling ConfigDeck to a hosting vendor.
- Add optional metrics suitable for private monitoring systems without including configuration values or user secrets.
- Evaluate additional release-signature verification and broader architecture support after repeatable CI coverage is available.

## Explicitly outside the current MVP

- Direct deployment-platform API integration.
- Kubernetes-specific orchestration.
- SSO/OIDC/LDAP, service accounts, and public automation APIs.
- Dynamic secrets, automatic credential rotation, or plaintext secret comparison.
- Background workers, horizontal replicas, or shared-network SQLite storage.

Security-sensitive proposals should begin with a threat-model and authorization review.
