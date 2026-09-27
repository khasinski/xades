# frozen_string_literal: true

module Xades
  # @api private
  module Digest
    # This gem always *signs* with SHA-256 (the only algorithm KSeF requires), but documents we
    # need to *verify* may legally use any of these (KSeF's own docs list SHA-1/256/384/512).
    ALGORITHMS = {
      "http://www.w3.org/2000/09/xmldsig#sha1" => OpenSSL::Digest::SHA1,
      "http://www.w3.org/2001/04/xmlenc#sha256" => OpenSSL::Digest::SHA256,
      "http://www.w3.org/2001/04/xmldsig-more#sha384" => OpenSSL::Digest::SHA384,
      "http://www.w3.org/2001/04/xmlenc#sha512" => OpenSSL::Digest::SHA512
    }.freeze

    def self.sha256_base64(bytes)
      base64(bytes, "http://www.w3.org/2001/04/xmlenc#sha256")
    end

    def self.base64(bytes, algorithm_uri)
      digest_class = ALGORITHMS.fetch(algorithm_uri) do
        raise UnsupportedAlgorithmError, "Unsupported digest algorithm: #{algorithm_uri.inspect}"
      end
      Base64.strict_encode64(digest_class.digest(bytes))
    end

    def self.supported?(algorithm_uri)
      ALGORITHMS.key?(algorithm_uri)
    end
  end
end
