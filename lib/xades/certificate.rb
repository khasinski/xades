# frozen_string_literal: true

module Xades
  # Wraps an X.509 certificate together with its private key, loaded from PEM or PKCS#12.
  class Certificate
    attr_reader :x509, :key

    def initialize(x509:, key:)
      unless key.is_a?(OpenSSL::PKey::RSA) || key.is_a?(OpenSSL::PKey::EC)
        raise UnsupportedKeyError,
              "key must be an RSA or EC private key"
      end

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
  end
end
