## [Unreleased]

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
