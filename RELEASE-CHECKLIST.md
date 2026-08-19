# Release checklist

- [ ] Copy only reviewed source and example settings files.
- [ ] Run `tests/StaticChecks.ps1` in PowerShell 7.
- [ ] Run Gitleaks and TruffleHog against the final repository and Git history.
- [ ] Confirm no personal path, username, organization, or production CA material remains.
- [ ] Test ML-DSA-87 key generation, certificate issuance, signing, and verification.
- [ ] Modify the test file and confirm verification fails.
- [ ] Change the signature context and confirm verification fails.
- [ ] Review the diff, create a clean repository, and commit only sanitized files.
- [ ] Enable GitHub secret scanning, Dependabot, and branch protection.
