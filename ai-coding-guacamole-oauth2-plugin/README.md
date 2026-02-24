# From Filing Tickets to Fixing Problems: AI-Assisted Development of Secure OAuth2 Authentication for Apache Guacamole

## White Paper

When a dependency breaks and upstream has no fix, AI-assisted development lets practitioners solve it themselves. This paper documents the investigation, CSRF vulnerability discovery, and secure replacement of Apache Guacamole's deprecated OAuth2 implicit flow.

**Author**: Gerry Burde
**Date**: February 2026

### CySA+ CS0-003 Domain Mapping
- **Security Operations**: SSO authentication infrastructure, identity provider integration
- **Vulnerability Management**: Remediating deprecated protocol usage (IETF-deprecated implicit flow)

### Contents
- [`paper/paper.md`](paper/paper.md) -- The white paper
- [`references/`](references/) — Links to upstream bugs and IETF specifications

### Related
- Source: [guacamole-auth-sso-oauth2](https://github.com/Gerry9000/guacamole-auth-sso-oauth2)
- Upstream: GUACAMOLE-1200, GUACAMOLE-1094, GUACAMOLE-805
