# frozen_string_literal: true

module CertificateHelper
  def build_rsa_certificate(cn: "Test Signer", serial: 1)
    key = OpenSSL::PKey::RSA.generate(2048)
    Xades::Certificate.new(x509: build_x509(key.public_to_pem, key, cn: cn, serial: serial), key: key)
  end

  def build_ec_certificate(curve: "prime256v1", cn: "Test EC Signer", serial: 1)
    key = OpenSSL::PKey::EC.generate(curve)
    Xades::Certificate.new(x509: build_x509(nil, key, cn: cn, serial: serial), key: key)
  end

  private

  def build_x509(_public_pem, key, cn:, serial:)
    cert = OpenSSL::X509::Certificate.new
    cert.serial = serial
    # Root-to-leaf RDN order (C, O, CN), matching conventional CA practice, so that the RFC2253
    # string form (which reverses ASN.1 order) reads the familiar "CN=...,O=...,C=..." way.
    cert.subject = OpenSSL::X509::Name.new([["C", "PL"], ["O", "Xades Test Suite"], ["CN", cn]])
    cert.issuer = OpenSSL::X509::Name.new([["C", "PL"], ["O", "Xades Test Suite"], ["CN", "Xades Test CA"]])
    cert.public_key = key.is_a?(OpenSSL::PKey::EC) ? key : key.public_key
    cert.not_before = Time.now - 60
    cert.not_after = Time.now + 3600
    cert.version = 2
    cert.sign(key, OpenSSL::Digest.new("SHA256"))
    cert
  end
end
