# Build, Publish, and Deploy

ConfigDeck separates public artifact production from environment-specific deployment.

## Public repository workflows

- `.github/workflows/ci.yml` validates Rust formatting, lint, tests, MSRV, dependencies, and the container build. It never publishes an image and has read-only permissions by default.
- `.github/workflows/release.yml` runs only for version tags matching `v*.*.*`. It publishes `ghcr.io/<repository-owner>/<repository-name>` with semantic-version and commit tags, an SBOM, provenance, and a GitHub attestation.
- GitHub Actions are pinned to full commit SHAs. Dependabot proposes updates for Cargo, Docker, and action dependencies.

The release workflow uses the repository-provided `GITHUB_TOKEN`; no registry password is required. Protect release tags and require CI before a tag is created.

## Deployment boundary

The public source repository does not contain notification-service credentials, server addresses, SSH keys, or deployment webhooks. A production operator should deploy an immutable image digest from a separate protected environment or private deployment repository.

A downstream deployment flow typically:

1. receives or selects a released image digest;
2. updates the protected platform or Compose configuration;
3. preserves `/data`, `/backup`, and the existing master-key secret;
4. waits for `/health` and `/ready`;
5. performs the smoke checks in `release-checklist.md`;
6. records the deployed digest and backup identifier.

If a deployment platform supports a webhook, store it as an environment secret in the private deployment workflow. Do not treat a missing webhook as a successful production deployment, and do not interpolate commit messages or other untrusted event text into shell commands.

## Dockerfile location

The Dockerfile intentionally remains at the repository root. ConfigDeck has one Rust runtime image and no separate Nginx, Supervisor, PHP-FPM, or frontend build configuration tree. The root location keeps Compose, local builds, and GitHub Actions conventional:

```bash
docker build -t configdeck:local .
docker compose build
```

If future deployment assets grow into several platform-specific files, they can be grouped under `deployment/` without changing the application architecture.
