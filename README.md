# Xades

[![CI](https://github.com/khasinski/xades/actions/workflows/main.yml/badge.svg)](https://github.com/khasinski/xades/actions/workflows/main.yml)

XAdES-BES / BASELINE-B (ETSI EN 319 132) XML signing and verification for pure Ruby (MRI). No
`xmlsec1` binary, no JVM -- just [Nokogiri](https://nokogiri.org/) (XML + Exclusive C14N) and
Ruby's built-in `openssl` (RSA / ECDSA).

This exists because Ruby has never had a maintained, general-purpose XAdES gem, while several
eIDAS-adjacent flows require one -- most concretely, **Poland's KSeF 2.0** e-invoicing system,
where authenticating with a certificate means signing an `AuthTokenRequest` document with
XAdES-BES (see [CIRFMF/ksef-docs](https://github.com/CIRFMF/ksef-docs)).

## What this is (and isn't)

Implements **XAdES-BES / BASELINE-B** only:

- Enveloped signatures (the signature is inserted as the last child of the signed document's root)
- Exclusive C14N (`http://www.w3.org/2001/10/xml-exc-c14n#`)
- RSA-SHA256 and ECDSA-SHA256 (P-256 / P-384 / P-521), with ECDSA `SignatureValue` encoded as raw
  `R || S` per RFC 4050/6931 -- not the DER form OpenSSL produces internally
- `SigningCertificate` (V1) or `SigningCertificateV2` (default; RFC 5035 `IssuerSerialV2`)
- PEM and PKCS#12 key/certificate loading

**Not implemented** (out of scope for this MVP): XAdES-T/-LT/-LTA (timestamps, revocation data,
archival), CAdES/PAdES, enveloping or detached signature formats, HSM integration, and certificate
trust/chain/revocation validation. `Xades::Bes.verify` checks that the signature is *structurally
and cryptographically correct against the certificate embedded in the document* -- it does not
tell you whether that certificate should be trusted.

**Status**: pre-1.0, early. The test suite includes real-world interop fixtures from other
projects (see `spec/fixtures/interop/SOURCES.md`) and a golden fixture matching KSeF's published
`AuthTokenRequest` schema, but this gem has not yet been independently cross-checked against a
third-party validator (`xmlsec1`, esig/dss) or a live KSeF test environment. Please verify against
your target system before relying on it for anything regulated, and open an issue if you do.

## Installation

```bash
bundle add xades
```

## Usage

```ruby
require "xades"

certificate = Xades::Certificate.from_pem(
  cert: File.read("cert.pem"),
  key: File.read("key.pem")
)
# or: Xades::Certificate.from_pkcs12(File.read("cert.p12"), "password")

signed_xml = Xades::Bes.sign(xml, certificate: certificate)

result = Xades::Bes.verify(signed_xml)
result.valid?  # => true
result.errors  # => []
```

`Xades::Bes.sign` accepts:

| option | default | |
|---|---|---|
| `certificate:` | *(required)* | an `Xades::Certificate` |
| `signing_time:` | `Time.now.utc` | embedded as `xades:SigningTime` |
| `signing_certificate_version:` | `:v2` | `:v2` (`SigningCertificateV2`/`IssuerSerialV2`) or `:v1` (`SigningCertificate`/`IssuerSerial`) |

The certificate's key type (RSA or EC) determines the signature algorithm automatically.

### KSeF example

```ruby
auth_token_request = <<~XML
  <AuthTokenRequest xmlns="http://ksef.mf.gov.pl/auth/token/2.1">
    <Challenge>#{challenge}</Challenge>
    <ContextIdentifier><Nip>#{nip}</Nip></ContextIdentifier>
    <SubjectIdentifierType>certificateSubject</SubjectIdentifierType>
  </AuthTokenRequest>
XML

signed = Xades::Bes.sign(auth_token_request, certificate: certificate)
# POST `signed` to /api/v2/auth/xades-signature
```

## Development

```bash
bin/setup
bundle exec rspec
bundle exec rubocop
```

The test suite (`spec/`) combines three kinds of coverage, modeled on how other languages'
XAdES libraries test themselves (`signxml` in Python, `xadesjs` in Node, `esig/dss` in Java --
see `spec/fixtures/interop/SOURCES.md`):

- **Unit specs** (`spec/xades/`) for each internal component
- **Conformance specs** (`spec/conformance/`), asserting the exact BASELINE-B structural
  requirements a signature must (and must not) satisfy, mirroring `esig/dss`'s
  `XAdESBaselineBTest` pattern
- **Interop specs** (`spec/interop/`), verifying real-world XAdES documents vendored from other
  projects' test suites, plus a golden fixture built against KSeF's published `AuthTokenRequest`
  schema and XAdES parameter constraints

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/khasinski/xades.

## License

The gem's own code is available as open source under the [MIT License](LICENSE.txt). Some test
fixtures under `spec/fixtures/interop/` are vendored from other projects under their own licenses
-- see `NOTICE` and `spec/fixtures/interop/SOURCES.md`.
