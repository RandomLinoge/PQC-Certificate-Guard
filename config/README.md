# Configuration and placeholders

This directory is the only place you need to inspect before a local test.

1. Copy `pqc-certificate-guard.settings.example.json` into `../src/`.
2. Rename the copy to `pqc-certificate-guard.settings.json`.
3. Replace the example lab, organization, country, OU, and context values.
4. Leave `OpenSslPath` empty for a PATH lookup, or set the executable path here.
5. Keep `Workspace` relative for a disposable lab, or set an isolated absolute path.

Do not add production CA keys, passwords, tokens, certificate enrollment secrets,
or personal workstation paths.
