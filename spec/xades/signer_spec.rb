# frozen_string_literal: true

RSpec.describe Xades::Signer do
  let(:xml) { '<Root xmlns="urn:test"><Payload>hello</Payload></Root>' }
  let(:certificate) { build_rsa_certificate }

  describe "#initialize" do
    it "defaults id_prefix to \"xades\"" do
      signed = described_class.new(certificate: certificate).sign(xml)
      doc = Nokogiri::XML(signed)
      expect(doc.at_xpath("//*[local-name()='Signature']")["Id"]).to start_with("xades-signature-")
    end

    it "uses a custom id_prefix for every generated Id" do
      signed = described_class.new(certificate: certificate, id_prefix: "acme").sign(xml)
      doc = Nokogiri::XML(signed)

      expect(doc.at_xpath("//*[local-name()='Signature']")["Id"]).to start_with("acme-signature-")
      expect(doc.at_xpath("//*[local-name()='KeyInfo']")["Id"]).to start_with("acme-keyinfo-")
      expect(doc.at_xpath("//*[local-name()='SignedProperties']")["Id"]).to start_with("acme-signedprops-")
    end

    it "raises ArgumentError through the public Signer API for an unknown signing_certificate_version" do
      expect do
        described_class.new(certificate: certificate, signing_certificate_version: :v9).sign(xml)
      end.to raise_error(ArgumentError, /:v1 or :v2/)
    end
  end

  describe "#sign" do
    it "raises MalformedDocumentError for input with no root element" do
      expect { described_class.new(certificate: certificate).sign("") }.to raise_error(Xades::MalformedDocumentError)
      expect { described_class.new(certificate: certificate).sign("   ") }.to raise_error(Xades::MalformedDocumentError)
    end

    it "accepts anything that responds to #to_s" do
      xml_like = Struct.new(:body) { def to_s = body }.new(xml)
      expect { described_class.new(certificate: certificate).sign(xml_like) }.not_to raise_error
    end

    it "each call generates fresh, non-colliding IDs" do
      signer = described_class.new(certificate: certificate)
      first = Nokogiri::XML(signer.sign(xml)).at_xpath("//*[local-name()='Signature']")["Id"]
      second = Nokogiri::XML(signer.sign(xml)).at_xpath("//*[local-name()='Signature']")["Id"]
      expect(first).not_to eq(second)
    end
  end
end
