# frozen_string_literal: true

RSpec.describe Xades::Builder::QualifyingProperties do
  let(:certificate) { build_rsa_certificate(cn: "Alice", serial: 7) }
  let(:signing_time) { Time.utc(2026, 1, 2, 3, 4, 5) }

  # Mirrors xadesjs's feature-by-feature test style (test/signed_xml/signing.ts): one example per
  # SignedSignatureProperties child, asserting both presence and value.
  describe "SigningTime" do
    it "renders as UTC xsd:dateTime with a Z suffix" do
      xml = described_class.build(certificate: certificate, signature_id: "sig", signed_properties_id: "sp",
                                  signing_time: signing_time)
      doc = Nokogiri::XML(xml)
      expect(doc.at_xpath("//*[local-name()='SigningTime']").text).to eq("2026-01-02T03:04:05Z")
    end
  end

  describe "SigningCertificateV2 (default)" do
    subject(:doc) do
      Nokogiri::XML(described_class.build(certificate: certificate, signature_id: "sig", signed_properties_id: "sp",
                                          signing_time: signing_time))
    end

    it "includes CertDigest with the certificate's SHA-256 digest" do
      digest_value = doc.at_xpath("//*[local-name()='SigningCertificateV2']//*[local-name()='DigestValue']").text
      expect(digest_value).to eq(certificate.sha256_digest_base64)
    end

    it "includes IssuerSerialV2 matching Certificate#issuer_serial_v2_base64" do
      expect(doc.at_xpath("//*[local-name()='IssuerSerialV2']").text).to eq(certificate.issuer_serial_v2_base64)
    end

    it "does not include the V1 IssuerSerial form" do
      expect(doc.at_xpath("//*[local-name()='IssuerSerial']")).to be_nil
    end
  end

  describe "SigningCertificate V1" do
    subject(:doc) do
      Nokogiri::XML(described_class.build(certificate: certificate, signature_id: "sig", signed_properties_id: "sp",
                                          signing_time: signing_time, version: :v1))
    end

    it "includes X509IssuerName and X509SerialNumber" do
      expect(doc.at_xpath("//*[local-name()='X509IssuerName']").text).to eq(certificate.issuer_name)
      expect(doc.at_xpath("//*[local-name()='X509SerialNumber']").text).to eq(certificate.serial)
    end

    it "does not include the V2 form" do
      expect(doc.at_xpath("//*[local-name()='SigningCertificateV2']")).to be_nil
    end
  end

  it "sets Target on QualifyingProperties to the given signature id" do
    xml = described_class.build(certificate: certificate, signature_id: "my-sig-id", signed_properties_id: "sp",
                                signing_time: signing_time)
    doc = Nokogiri::XML(xml)
    expect(doc.root["Target"]).to eq("#my-sig-id")
  end

  it "raises ArgumentError for an unknown version" do
    expect do
      described_class.build(certificate: certificate, signature_id: "sig", signed_properties_id: "sp",
                            signing_time: signing_time, version: :v3)
    end.to raise_error(ArgumentError, /:v1 or :v2/)
  end
end
