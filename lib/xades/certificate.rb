# frozen_string_literal: true

module Xades
  # Wraps an X.509 certificate together with its private key, loaded from PEM or PKCS#12.
  class Certificate
    attr_reader :x509, :key

    # KSeF's docs require a minimum 2048-bit RSA key; a weaker key would otherwise be accepted
    # silently here and only rejected much later, opaquely, by whatever system verifies it.
    MINIMUM_RSA_KEY_BITS = 2048

    def initialize(x509:, key:)
      validate_key_type!(key)
      validate_key_strength!(key)
      validate_key_matches_certificate!(x509, key)

      @x509 = x509
      @key = key
    end

    def self.from_pem(cert:, key:, password: nil)
      new(x509: OpenSSL::X509::Certificate.new(cert), key: OpenSSL::PKey.read(key, password))
    end

    # +pkcs12+ may be raw PKCS#12 bytes, an IO-like object, or a path to a .p12/.pfx file.
    def self.from_pkcs12(pkcs12, password)
      data = if pkcs12.respond_to?(:read)
               pkcs12.read
             elsif pkcs12.is_a?(String) && !pkcs12.include?("\x00") && File.exist?(pkcs12)
               File.binread(pkcs12)
             else
               pkcs12
             end
      p12 = OpenSSL::PKCS12.new(data, password)
      new(x509: p12.certificate, key: p12.key)
    end

    def rsa?
      key.is_a?(OpenSSL::PKey::RSA)
    end

    def ec?
      key.is_a?(OpenSSL::PKey::EC)
    end

    def base64_der
      Base64.strict_encode64(x509.to_der)
    end

    def sha256_digest_base64
      Xades::Digest.sha256_base64(x509.to_der)
    end

    # RFC 2253 string form of the issuer DN, as used by ds:X509IssuerName (SigningCertificate V1).
    def issuer_name
      x509.issuer.to_s(OpenSSL::X509::Name::RFC2253).force_encoding(Encoding::UTF_8)
    end

    def serial
      x509.serial.to_s
    end

    def expired?(at: Time.now)
      at > x509.not_after
    end

    def not_yet_valid?(at: Time.now)
      at < x509.not_before
    end

    def valid_at?(time)
      !expired?(at: time) && !not_yet_valid?(at: time)
    end

    # DER-encoded IssuerSerial (RFC 5035 IssuerSerial: SEQUENCE { GeneralNames, CertificateSerialNumber }),
    # base64-encoded, as used by xades:IssuerSerialV2 (SigningCertificate V2). Verified byte-for-byte against
    # a real DSS-generated fixture during development.
    def issuer_serial_v2_base64
      self.class.issuer_serial_v2_base64_for(x509)
    end

    def self.issuer_serial_v2_base64_for(x509)
      issuer_asn1 = OpenSSL::ASN1.decode(x509.issuer.to_der)
      general_name = OpenSSL::ASN1::ASN1Data.new([issuer_asn1], 4, :CONTEXT_SPECIFIC)
      general_names = OpenSSL::ASN1::Sequence.new([general_name])
      serial_asn1 = OpenSSL::ASN1::Integer.new(x509.serial)
      issuer_serial = OpenSSL::ASN1::Sequence.new([general_names, serial_asn1])
      Base64.strict_encode64(issuer_serial.to_der)
    end

    private

    def validate_key_type!(key)
      return if key.is_a?(OpenSSL::PKey::RSA) || key.is_a?(OpenSSL::PKey::EC)

      raise UnsupportedKeyError, "key must be an RSA or EC private key, got #{key.class}"
    end

    def validate_key_strength!(key)
      return unless key.is_a?(OpenSSL::PKey::RSA)
      return if key.n.num_bits >= MINIMUM_RSA_KEY_BITS

      raise UnsupportedKeyError, "RSA key is #{key.n.num_bits} bits, minimum is #{MINIMUM_RSA_KEY_BITS}"
    end

    def validate_key_matches_certificate!(x509, key)
      return if public_key_der(x509.public_key) == public_key_der(key)

      raise CertificateKeyMismatchError, "the certificate's public key does not match the given private key"
    end

    # A private key's own #public_key and a certificate's #public_key aren't directly comparable
    # for EC (the former is a bare OpenSSL::PKey::EC::Point, the latter a full OpenSSL::PKey::EC),
    # so we normalize both down to the raw EC point encoding; for RSA, #to_der on the public key
    # portion of either is already directly comparable.
    def public_key_der(key_or_cert_public_key)
      if key_or_cert_public_key.is_a?(OpenSSL::PKey::EC)
        key_or_cert_public_key.public_key.to_bn.to_s(2)
      elsif key_or_cert_public_key.is_a?(OpenSSL::PKey::RSA)
        key_or_cert_public_key.public_key.to_der
      else
        key_or_cert_public_key.to_der
      end
    end
  end
end
