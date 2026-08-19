<p align="center">
  <img src="https://github.com/RandomLinoge/PQC-Certificate-Guard/blob/main/CertificateGuard-Logo.jpg">
  <p align="center">Experimental PowerShell laboratory for ML-DSA and SLH-DSA X.509 certificates and detached file signatures.</p>
  <p align="center">
  </a>
    <a href="https://github.com/RandomLinoge/PQC-Certificate-Guard">
      <img src="https://img.shields.io/badge/Version-1.0.0-rc1-darkgreen">
        <img src="https://img.shields.io/badge/Release%20Date-August%202622-blue">
  <img src="https://img.shields.io/badge/powershell-100%25-blue?style=plastic">
    </a>
  </p>
</p>

# PQC Certificate Guard

PQC Certificate Guard is an experimental Windows PowerShell laboratory for private X.509 hierarchies and detached file signatures using OpenSSL 3.5+.

## Cryptographic scope

- ML-DSA-44, ML-DSA-65, and ML-DSA-87 from FIPS 204.
- All standardized SHA2 and SHAKE SLH-DSA parameter sets from FIPS 205.
- X.509 root and file-signing certificate generation.
- Detached signature creation with a context string.
- Independent certificate-chain and file-signature verification.

ML-DSA-87 and the 256-bit SLH-DSA families are already the highest standardized security-category options exposed by OpenSSL 3.5. ML-KEM is a key-encapsulation algorithm and is intentionally excluded from this signing-only workflow.

## Configure before testing

1. Install OpenSSL 3.5 or later with ML-DSA and SLH-DSA in the active provider.
2. Copy `config/pqc-certificate-guard.settings.example.json` to `src/pqc-certificate-guard.settings.json`.
3. Edit only that copied settings file:

   - Leave `OpenSslPath` empty to use `openssl.exe` from `PATH`, or set its full path.
   - Leave `Workspace` as `workspace` for a repository-relative disposable lab, or set a dedicated absolute folder.
   - Select `ML-DSA-87` for the strongest standardized ML-DSA profile.
   - Select an `SLH-DSA-*-256*` profile when testing a hash-based Category 5 alternative.
   - Set a unique, stable context string for the signing application.

4. Run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
& .\src\PQC-Certificate-Guard.ps1
```

## Safe first test

1. Run **Setup doctor** and confirm OpenSSL 3.5+ and algorithm support.
2. Use a disposable repository-relative workspace.
3. Generate a lab root and file signer.
4. Sign `test.txt` and verify the chain and signature.
5. Modify one byte and confirm verification fails.
6. Restore the file, change the context string, and confirm verification fails.
7. Never reuse the disposable root as a production trust anchor.

## Algorithm guidance

| Algorithm | Use |
|---|---|
| ML-DSA-65 | Balanced operational signing profile |
| ML-DSA-87 | Highest standardized ML-DSA security category |
| SLH-DSA-*-256s | Smaller Category 5 hash-based signature, very slow |
| SLH-DSA-*-256f | Faster Category 5 hash-based operation, very large signature |

## Status

Research preview for private laboratory PKI. The generated certificates are not publicly trusted and the project has not received an independent security audit.

## License

Apache License 2.0.
