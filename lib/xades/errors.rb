# frozen_string_literal: true

module Xades
  class Error < StandardError; end

  # Raised when a key type or curve isn't supported (only RSA and EC P-256/P-384/P-521 are).
  class UnsupportedKeyError < Error; end

  # Raised when the input XML cannot be parsed or is missing an expected signature structure.
  class MalformedDocumentError < Error; end
end
