# Compatibility

OpenSSL 3.5 provides ML-DSA-44, ML-DSA-65, ML-DSA-87, and the twelve standardized SLH-DSA SHA2/SHAKE parameter sets used by this project.

Generated X.509 certificates require relying software that understands the corresponding PQC algorithm identifiers. A successful OpenSSL verification does not establish compatibility with Windows certificate stores, browsers, public CAs, signing portals, or third-party PKI products.

Composite or hybrid X.509 certificates are outside the current release because interoperable standards and provider support must be established separately.
