# frozen_string_literal: true

module Xades
  class Error < StandardError; end

  # Raised when a key type or curve isn't supported (only RSA and EC P-256/P-384/P-521 are).
  class UnsupportedKeyError < Error; end

  # Raised when a document declares a canonicalization or digest algorithm this gem doesn't
  # implement (e.g. C14N 1.1, or a digest other than SHA-256/384/512/SHA-1).
  class UnsupportedAlgorithmError < Error; end

  # Raised when the input XML cannot be parsed or is missing an expected signature structure.
  class MalformedDocumentError < Error; end
end
