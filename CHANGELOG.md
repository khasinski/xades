## [Unreleased]

## [0.2.0] - 2026-09-27

- Added `Xades::Bes.verify!`/`Xades::Verifier.verify!`: raises `Xades::VerificationError` (message
  joins every `Result#errors` entry) instead of returning a `Result` you have to check `.valid?`
  on. Returns `true` on success.
- `signing_time:` now accepts anything that responds to `#to_time` (`Date`, `DateTime`,
  `ActiveSupport::TimeWithZone`, ...) in addition to `Time`, normalized up front with a clear
  `ArgumentError` for anything else -- previously a bare `Date` failed with a `NoMethodError` on
  `#utc` deep inside a builder.
- **Breaking**: `Xades::Certificate.new` (and therefore `.from_pem`/`.from_pkcs12`) now validates
  that the private key actually matches the certificate's public key
  (`Xades::CertificateKeyMismatchError` if not) and that an RSA key is at least 2048 bits
  (`Xades::UnsupportedKeyError` if not, matching KSeF's documented minimum). Previously a
  mismatched cert/key pair was accepted silently and produced a signature that could never verify.
- **Breaking**: `Xades::Bes.sign`/`Signer#sign` now raise `Xades::CertificateValidityError` if the
  certificate is expired or not yet valid at `signing_time`, unless
  `allow_invalid_certificate_period: true` is passed. New `Certificate#expired?`,
  `#not_yet_valid?`, `#valid_at?` for checking this yourself.
- **Breaking**: now requires Ruby >= 4.0 (was >= 3.2). CI matrix and `.rubocop.yml`'s
  `TargetRubyVersion` updated to match.
- `Verifier` now reads and respects a document's actually-declared canonicalization method
  (Exclusive C14N, plain C14N 1.0, or C14N 1.1, including the XMLDSig-implicit-default cases),
  digest algorithm (SHA-1/256/384/512) and signature algorithm (RSA/ECDSA with any of those
  digests), instead of assuming its own signing defaults. Found and fixed via real-world
  signatures from Denmark, the UK and Spain (Facturae) -- see `spec/fixtures/interop/SOURCES.md`.
- Fixed: `Verifier` picked the wrong `Reference` as "the document" on signatures that carry more
  than one untyped `Reference` (e.g. a real Facturae signature that also protects `KeyInfo`); it
  now specifically looks for `URI=""`.
- Added unit specs for `C14N`, `Digest`, `Util`, and a from-scratch `Verifier` spec covering every
  supported signature-method/digest combination directly (not only via `Signer`, which only ever
  produces SHA-256).

## [0.1.0] - 2026-09-27

- Initial release
