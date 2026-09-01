# Test doubles

Fixtures and servers the integration suite needs but that are not part of the
product.

| Contents | Milestone |
| --- | --- |
| A mock OIDC provider, for testing Warden as a relying party | M4 |
| A mock SAML identity provider | M4 |
| A corpus of hostile SAML assertions — signature wrapping, XXE, mismatched audiences, replayed IDs | M4 |

The hostile corpus is the point of this directory. SPEC §17.1 names SAML signature
wrapping and XXE as threats to mitigate explicitly, and the only credible way to show
they are mitigated is a set of assertions that exercise each one.
