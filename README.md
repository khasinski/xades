# Xades

[![CI](https://github.com/khasinski/xades/actions/workflows/main.yml/badge.svg)](https://github.com/khasinski/xades/actions/workflows/main.yml)

XAdES-BES / BASELINE-B (ETSI EN 319 132) XML signing and verification for pure Ruby (MRI). No
`xmlsec1` binary, no JVM -- just [Nokogiri](https://nokogiri.org/) (XML + Exclusive C14N) and
Ruby's built-in `openssl` (RSA / ECDSA).

This exists because Ruby has never had a maintained, general-purpose XAdES gem, while several
eIDAS-adjacent flows require one. XAdES-BES is an EU-wide standard, not a Polish one -- **Poland's
KSeF 2.0** e-invoicing system is this gem's primary driver (authenticating with a certificate means
signing an `AuthTokenRequest` document with XAdES-BES, see
[CIRFMF/ksef-docs](https://github.com/CIRFMF/ksef-docs)), but the same signer/verifier works for
any XAdES-BES use case: Spain's Facturae, generic eIDAS-adjacent e-invoicing, Peppol, etc.

### Tested against real-world signatures from other countries

`Xades::Bes.verify` doesn't just round-trip against its own output -- the test suite includes real,
independently-produced signatures from **Denmark, the United Kingdom, Spain (Facturae), Slovakia,
Hungary and Austria**, plus generic ETSI plugtest vectors, vendored from other projects' test
suites (see [`spec/fixtures/interop/SOURCES.md`](spec/fixtures/interop/SOURCES.md) for exactly
which file, from where, and what it's for). These aren't decorative: verifying against them during
development caught real bugs -- Verifier used to hardcode Exclusive C14N and SHA-256 and assume the
first untyped `Reference` was always "the document," none of which held for every one of these
countries' tools. Verifier now reads the canonicalization, digest and signature algorithm a
document actually declares (KSeF's own docs list several of each) rather than assuming its own
defaults.

## What this is (and isn't)

**Signing** always produces XAdES-BES / BASELINE-B in one specific, KSeF-compatible shape:

- Enveloped signatures (the signature is inserted as the last child of the signed document's root)
- Exclusive C14N (`http://www.w3.org/2001/10/xml-exc-c14n#`)
- RSA-SHA256 and ECDSA-SHA256 (P-256 / P-384 / P-521), with ECDSA `SignatureValue` encoded as raw
  `R || S` per RFC 4050/6931 -- not the DER form OpenSSL produces internally
- `SigningCertificate` (V1) or `SigningCertificateV2` (default; RFC 5035 `IssuerSerialV2`)
- PEM and PKCS#12 key/certificate loading

**Verification** is deliberately more permissive, since a document you didn't produce may
legitimately use a different (still XAdES-BES-conformant) combination: it reads and respects the
actual declared canonicalization method (Exclusive C14N, plain C14N 1.0 or C14N 1.1, including the
implicit-default cases the XMLDSig spec allows), digest algorithm (SHA-1/256/384/512), and
signature algorithm (RSA or ECDSA with any of those digests) rather than assuming its own defaults.

**Not implemented** (out of scope for this MVP -- see "What's next" below for why): XAdES-T/-LT/-LTA
(timestamps, revocation data, archival), CAdES/PAdES, detached signatures, HSM integration, and
certificate trust/chain/revocation validation. `Xades::Bes.verify` checks that the signature is
*structurally and cryptographically correct against the certificate embedded in the document* -- it
does not tell you whether that certificate should be trusted. Enveloping (as opposed to enveloped)
signatures can be *verified* if they happen to use a `URI=""`-style reference, but this gem cannot
yet *produce* them.

**Status**: pre-1.0, early. The test suite includes real-world interop fixtures from other
projects (see `spec/fixtures/interop/SOURCES.md`) and a golden fixture matching KSeF's published
`AuthTokenRequest` schema, but this gem has not yet been independently cross-checked against a
third-party validator (`xmlsec1`, esig/dss) or a live KSeF test environment. Please verify against
your target system before relying on it for anything regulated, and open an issue if you do.

## What's next

Roughly in priority order, based on what would make this gem more useful versus what would turn it
into a different (and already well-served, e.g. by esig/dss) product:

1. **Enveloping signature support** (signing, not just verifying). KSeF's own docs explicitly
   accept enveloping alongside enveloped, and Spain's Facturae typically produces enveloping
   signatures too -- this is the one gap that's both cheap-ish to close and clearly wanted by more
   than one target platform.
2. **A small CLI** (`xades sign in.xml --cert ... --key ... -o out.xml` / `xades verify signed.xml`)
   so the gem is usable without writing Ruby, e.g. from a shell script or another language's CI job.
3. **More golden fixtures against live test environments**, not just published schemas -- starting
   with actually exchanging a signed `AuthTokenRequest` with KSeF's test API, and ideally a Facturae
   test endpoint too.
4. **XAdES-T** (RFC 3161 timestamping) as an *opt-in* addition on top of an existing BES signature,
   kept separate from the core `sign`/`verify` API. This is the most-requested "next tier" feature
   for any XAdES library, but full -LT/-LTA support is a much bigger, fundamentally different scope
   (revocation data embedding, and -LTA specifically requires *periodically re-timestamping* a
   signature over its lifetime -- an ongoing operational process, not a one-shot `sign` call) --
   likely a separate gem rather than a feature of this one, if it happens at all.
5. **Deliberately not planned**: certificate trust/chain/revocation validation. Doing this properly
   means an EU Trusted List (LOTL/EUTL) integration, OCSP/CRL fetching, and trust anchor management
   -- at that point you're rebuilding a slice of esig/dss. A partial version would be worse than
   none: it would look like a real trust check while giving false confidence. If you need this,
   pair `Xades::Bes.verify`'s structural/cryptographic check with a dedicated validator instead.

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

- **Unit specs** (`spec/xades/`) for each internal component, including a from-scratch (not via
  `Signer`) matrix in `verifier_spec.rb` proving every RSA/ECDSA x SHA-1/256/384/512 combination
  `Verifier` claims to support actually verifies
- **Conformance specs** (`spec/conformance/`), asserting the exact BASELINE-B structural
  requirements a signature must (and must not) satisfy, mirroring `esig/dss`'s
  `XAdESBaselineBTest` pattern
- **Interop specs** (`spec/interop/`): a golden fixture built against KSeF's published
  `AuthTokenRequest` schema, plus real-world signatures vendored from other countries/tools
  (`multi_country_fixtures_spec.rb`) and from other projects' own test suites
  (`vendored_fixtures_spec.rb`) -- see `spec/fixtures/interop/SOURCES.md` for what each file is and
  what interop bug (if any) it caught during development

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/khasinski/xades.

## License

The gem's own code is available as open source under the [MIT License](LICENSE.txt). Some test
fixtures under `spec/fixtures/interop/` are vendored from other projects under their own licenses
-- see `NOTICE` and `spec/fixtures/interop/SOURCES.md`.
