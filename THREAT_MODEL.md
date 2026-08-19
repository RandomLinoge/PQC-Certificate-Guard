# Threat model

## Protected assets

- Root and signer private keys.
- Authenticity of signed files.
- Certificate-chain integrity.
- Context-string consistency.
- Integrity of the selected OpenSSL executable and provider.

## Trust boundaries

- OpenSSL 3.5+ and its active provider are trusted dependencies.
- The workspace contains sensitive generated material.
- The settings JSON is operator-controlled input and contains no passphrase.
- The root is a private laboratory trust anchor.

## Principal threats

- Root-key theft or accidental publication.
- Executable or provider substitution.
- Signing the wrong artifact.
- Verifying against a stale signer public key.
- Context mismatch.
- Confusing a valid private chain with public WebPKI trust.
- Recursive discovery of unrelated private keys outside the configured workspace.

## Controls

- Repository-bounded path discovery.
- Explicit algorithm capability trials.
- Separate chain and detached-signature validation.
- Fresh public-key extraction from the selected signer certificate.
- Context-bound signing and verification.
- Private-material and path guardrails in automated tests.
