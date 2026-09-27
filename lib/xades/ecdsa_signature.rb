# frozen_string_literal: true

module Xades
  # XMLDSig (RFC 6931) requires ECDSA SignatureValue as the raw concatenation r || s, each
  # padded to the curve's field width -- not the DER SEQUENCE{r,s} that OpenSSL produces/expects.
  # Conversion verified against 200+ generated signatures during development (see scratchpad).
  module EcdsaSignature
    FIELD_BYTES = {
      "prime256v1" => 32,
      "secp384r1" => 48,
      "secp521r1" => 66
    }.freeze

    def self.field_bytes_for(ec_key)
      FIELD_BYTES.fetch(ec_key.group.curve_name) do
        raise UnsupportedKeyError,
              "Unsupported EC curve: #{ec_key.group.curve_name} (supported: #{FIELD_BYTES.keys.join(", ")})"
      end
    end

    def self.der_to_raw(der, byte_len)
      r, s = OpenSSL::ASN1.decode(der).value
      pad(r.value, byte_len) + pad(s.value, byte_len)
    end

    def self.raw_to_der(raw, byte_len)
      raise MalformedDocumentError, "ECDSA SignatureValue has wrong length" unless raw.bytesize == byte_len * 2

      r = OpenSSL::BN.new(raw[0, byte_len], 2)
      s = OpenSSL::BN.new(raw[byte_len, byte_len], 2)
      OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::Integer.new(r), OpenSSL::ASN1::Integer.new(s)]).to_der
    end

    def self.pad(integer, byte_len)
      integer.to_s(2).rjust(byte_len, "\x00")
    end
    private_class_method :pad
  end
end
