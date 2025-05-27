# System Patterns

## Architecture Overview
CaddyPAW is implemented as a Caddy plugin. It integrates with an authentication service (`github.com/charleshuang3/authn`).

## Key Technical Decisions
- Integration with `github.com/charleshuang3/authn` for OAuth/OIDC client functionality.
- Storing authentication state using server cookies and JWT tokens.
- Integration with a firewall via `github.com/charleshuang3/authn` for IP banning.

## Design Patterns in Use
[List and briefly explain any design patterns being used]

## Component Relationships
[Describe how different components of the system interact]

## Critical Implementation Paths
[Highlight any critical or complex parts of the implementation]
