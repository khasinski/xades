# Provenance of vendored interop fixtures

All files in this directory were copied unmodified from
[`XML-Security/signxml`](https://github.com/XML-Security/signxml) (`test/xades/`), Apache License
2.0. See `NOTICE` at the gem root for the required attribution.

signxml's own test suite in turn traces several of these files to the interoperability test corpus
of the [esig/dss](https://github.com/esig/dss) project (LGPL-2.1) and, further back, to the ETSI
XAdES plugtests -- the filenames (`dss-signed*`, `dss1788-*`) reflect that lineage. They are
vendored here purely as XML *test data* (signed documents used to check our verifier's behavior),
not as code.

| File | Used for |
|---|---|
| `dss-signed.xml` | Positive case: a real DSS-generated, RSA-signed, enveloped XAdES-BASELINE-B-shaped signature with `SigningCertificateV2`. Our verifier must accept it. |
| `xades-extended-epes.xml` | An **enveloping** (not enveloped) XAdES-EPES signature. Documents a real scope limitation: this gem's `Verifier` only understands the enveloped, `URI=""` reference shape it itself produces (see README). Expected to fail with "missing document Reference in SignedInfo" for that reason, not because the signature is actually invalid. |
| `dss-signed-altered-signedPropsRemoved.xml` | Negative: `SignedProperties`/its `Reference` was stripped after signing. Must fail. |
| `nonconformant-dss-signed-altered-refRemoved.xml` | Negative: the main document `Reference` was removed after signing. Must fail. |
| `xades-wrong-sign-cert-digest.xml` | Negative: `SigningCertificate`'s `CertDigest` doesn't match the embedded certificate. Exercises `Verifier#verify_signing_certificate_binding`. |
| `xades-sign-cert-v2-wrong-digest.xml` | Same as above, `SigningCertificateV2` form. |
| `xades-sign-cert-v2-wrong-issuer-serial.xml` | Negative: `IssuerSerialV2` doesn't match the embedded certificate's actual issuer/serial. Exercises `Verifier#verify_issuer_serial_v2_binding`. |
