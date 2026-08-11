# Security Policy

## Intended Use

This repository is a demo starter for local development and competition prototyping. It is not production-hardened.

## Reporting

If you discover a security issue in the demo code, avoid publishing exploit details in public issues before maintainers have had a chance to review and patch the problem.

## Current Limitations

- The command execution tool is a demo interface and should remain disabled by default.
- No authentication or authorization layer is included.
- No audit persistence, secrets vault, or sandbox isolation is provided.
- Real model integrations depend on external provider security controls.

## Deployment Warning

Do not deploy this project to production or expose it to untrusted users without adding:

- authentication
- authorization
- rate limiting
- action approval gates
- audit logging
- secure secret management
