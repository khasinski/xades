# frozen_string_literal: true

RSpec.describe Xades::Certificate do
  let(:certificate) { build_rsa_certificate(cn: "Alice", serial: 99) }

  it "loads from PEM cert + key" do
    key = OpenSSL::PKey::RSA.generate(2048)
    x509 = OpenSSL::X509::Certificate.new
    x509.serial = 1
    x509.subject = OpenSSL::X509::Name.parse("/CN=Test")
    x509.issuer = x509.subject
    x509.public_key = key.public_key
    x509.not_before = Time.now
    x509.not_after = Time.now + 3600
    x509.sign(key, OpenSSL::Digest.new("SHA256"))

    loaded = described_class.from_pem(cert: x509.to_pem, key: key.to_pem)

    expect(loaded.x509.to_der).to eq(x509.to_der)
    expect(loaded).to be_rsa
  end

  it "loads from PKCS#12" do
    key = OpenSSL::PKey::RSA.generate(2048)
    x509 = OpenSSL::X509::Certificate.new
    x509.serial = 2
    x509.subject = OpenSSL::X509::Name.parse("/CN=Test P12")
    x509.issuer = x509.subject
    x509.public_key = key.public_key
    x509.not_before = Time.now
    x509.not_after = Time.now + 3600
    x509.sign(key, OpenSSL::Digest.new("SHA256"))
    p12 = OpenSSL::PKCS12.create("s3cr3t", "test", key, x509)

    loaded = described_class.from_pkcs12(p12.to_der, "s3cr3t")

    expect(loaded.x509.to_der).to eq(x509.to_der)
  end

  it "rejects unsupported key types" do
    expect do
      described_class.new(x509: certificate.x509, key: Object.new)
    end.to raise_error(Xades::UnsupportedKeyError)
  end

  it "exposes the certificate as base64 DER" do
    expect(Base64.decode64(certificate.base64_der)).to eq(certificate.x509.to_der)
  end

  it "computes the SHA-256 digest of the DER-encoded certificate" do
    expect(Base64.decode64(certificate.sha256_digest_base64)).to eq(OpenSSL::Digest::SHA256.digest(certificate.x509.to_der))
  end

  it "renders the issuer name as an RFC 2253 string" do
    expect(certificate.issuer_name).to eq("CN=Xades Test CA,O=Xades Test Suite,C=PL")
  end

  it "renders the serial number as a decimal string" do
    expect(certificate.serial).to eq("99")
  end

  describe "#issuer_serial_v2_base64" do
    it "matches the DSS-generated reference vector for an equivalent issuer/serial" do
      # Verified byte-for-byte against a real esig/dss-generated XAdES-BES sample during development.
      key = OpenSSL::PKey::RSA.generate(2048)
      x509 = OpenSSL::X509::Certificate.new
      x509.serial = 10
      x509.subject = OpenSSL::X509::Name.new([["CN", "good-user"], ["O", "Nowina Solutions"], ["OU", "PKI-TEST"],
                                              ["C", "LU"]])
      x509.issuer = OpenSSL::X509::Name.new([["CN", "good-ca"], ["O", "Nowina Solutions"], ["OU", "PKI-TEST"],
                                             ["C", "LU"]])
      x509.public_key = key.public_key
      x509.not_before = Time.now
      x509.not_after = Time.now + 3600
      x509.sign(key, OpenSSL::Digest.new("SHA256"))
      cert = described_class.new(x509: x509, key: key)

      expect(cert.issuer_serial_v2_base64).to eq(
        "MFYwUaRPME0xEDAOBgNVBAMMB2dvb2QtY2ExGTAXBgNVBAoMEE5vd2luYSBTb2x1dGlvbnMxETAPBgNVBAsMCFBLSS1URVNUMQswCQYDVQQGEwJMVQIBCg=="
      )
    end

    it "round-trips through ASN.1 as SEQUENCE{ SEQUENCE{ [4] EXPLICIT Name }, INTEGER serial }" do
      der = Base64.decode64(certificate.issuer_serial_v2_base64)
      outer = OpenSSL::ASN1.decode(der)
      general_names, serial = outer.value

      expect(outer.tag_class).to eq(:UNIVERSAL)
      expect(general_names.value.first.tag).to eq(4)
      expect(general_names.value.first.tag_class).to eq(:CONTEXT_SPECIFIC)
      expect(serial.value).to eq(certificate.x509.serial)
    end
  end
end
