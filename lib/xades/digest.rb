# frozen_string_literal: true

module Xades
  # @api private
  module Digest
    def self.sha256_base64(bytes)
      Base64.strict_encode64(OpenSSL::Digest::SHA256.digest(bytes))
    end
  end
end
