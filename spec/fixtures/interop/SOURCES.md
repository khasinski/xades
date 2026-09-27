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

Real-world signatures from other EU countries/plugtest sources -- these are ordinary valid
signatures produced by other tools, not adversarial fixtures, and finding real interop problems
against them is exactly why they're here (see git history/CHANGELOG for what each one caught):

| File | Country / source | Used for |
|---|---|---|
| `dk_tl-sn21.xml` | Denmark | Positive: real enveloped signature, verifies as-is. |
| `Signature-X-UK_ASC-2.xml` | United Kingdom (ETSI plugtest) | Positive. Its `SignedProperties` `Reference` has **no `Transforms` element at all** -- caught a bug where `Verifier` hardcoded Exclusive C14N instead of applying the XMLDSig-mandated implicit plain C14N 1.0 default. |
| `factura_ejemplo2_32v1.xml` | Spain (Facturae) | Positive. RSA-SHA1 signature (Facturae's older profile) and **three** References including one protecting `KeyInfo` -- caught a bug where `Verifier` grabbed the first untyped `Reference` (the `KeyInfo` one) instead of specifically the `URI=""` one for the document. |
| `TEST_S1a_C1a_InTL_VALID.xml` | ETSI plugtest (international) | Positive: enveloped signature using an XPath filter transform alongside `enveloped-signature`; verifies correctly since both approaches exclude the same `Signature` subtree. |
| `Signature-X-SK_DIT-1.xml` | Slovakia (ETSI plugtest) | Negative (scope): enveloping, not enveloped. Same documented limitation as `xades-extended-epes.xml`. |
| `Signature-X-HU_POL-3.xml` | Hungary (ETSI plugtest) | Negative (scope): enveloping. |
| `X_AT_SIT_1.xml` | Austria (ETSI plugtest) | Negative (scope): enveloping. |
