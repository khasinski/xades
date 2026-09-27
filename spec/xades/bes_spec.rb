# frozen_string_literal: true

RSpec.describe Xades::Bes do
  let(:xml) do
    '<AuthTokenRequest xmlns="urn:test"><Challenge>abc-123</Challenge><ContextIdentifier><Nip>1234567890</Nip></ContextIdentifier></AuthTokenRequest>'
  end

  describe "round-trip sign + verify" do
    it "signs and verifies with an RSA certificate, SigningCertificateV2 (default)" do
      signed = described_class.sign(xml, certificate: build_rsa_certificate)
      expect(described_class.verify(signed)).to be_valid
    end

    it "signs and verifies with an RSA certificate, SigningCertificate V1" do
      signed = described_class.sign(xml, certificate: build_rsa_certificate, signing_certificate_version: :v1)
      expect(described_class.verify(signed)).to be_valid
    end

    %w[prime256v1 secp384r1 secp521r1].each do |curve|
      it "signs and verifies with an EC (#{curve}) certificate" do
        signed = described_class.sign(xml, certificate: build_ec_certificate(curve: curve))
        expect(described_class.verify(signed)).to be_valid
      end
    end
  end

  describe "resulting document structure" do
    subject(:doc) { Nokogiri::XML(described_class.sign(xml, certificate: build_rsa_certificate)) }

    it "appends the signature as a child of the document root (enveloped)" do
      expect(doc.root.at_xpath("./*[local-name()='Signature']")).not_to be_nil
    end

    it "includes SigningTime" do
      expect(doc.at_xpath("//*[local-name()='SigningTime']").text).to match(/\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\z/)
    end

    it "uses SigningCertificateV2 with IssuerSerialV2 by default, no bare SigningCertificate/IssuerSerial" do
      expect(doc.at_xpath("//*[local-name()='SigningCertificateV2']")).not_to be_nil
      expect(doc.at_xpath("//*[local-name()='IssuerSerialV2']")).not_to be_nil
      expect(doc.at_xpath("//*[local-name()='SigningCertificate']")).to be_nil
    end

    it "embeds the signer's certificate in KeyInfo/X509Data/X509Certificate" do
      cert_node = doc.at_xpath("//*[local-name()='X509Certificate']")
      expect(cert_node).not_to be_nil
      expect { OpenSSL::X509::Certificate.new(Base64.decode64(cert_node.text)) }.not_to raise_error
    end

    it "declares exclusive C14N as the canonicalization method" do
      expect(doc.at_xpath("//*[local-name()='CanonicalizationMethod']")["Algorithm"]).to eq(Xades::Algorithms::C14N_EXCLUSIVE)
    end

    it "references both the document (URI=\"\") and the SignedProperties (by Type)" do
      references = doc.xpath("//*[local-name()='Reference']")
      expect(references.size).to eq(2)
      expect(references.map { |r| r["URI"] }).to include("")
      expect(references.find { |r| r["Type"] == Xades::Algorithms::XADES_SIGNED_PROPERTIES_TYPE }).not_to be_nil
    end
  end

  describe "signing_time option" do
    it "uses the given time instead of Time.now" do
      time = Time.utc(2026, 4, 1, 9, 0, 0)
      signed = described_class.sign(xml, certificate: build_rsa_certificate, signing_time: time)
      doc = Nokogiri::XML(signed)
      expect(doc.at_xpath("//*[local-name()='SigningTime']").text).to eq("2026-04-01T09:00:00Z")
    end
  end

  describe "tamper detection" do
    let(:signed) { described_class.sign(xml, certificate: build_rsa_certificate) }

    it "rejects a modified document body" do
      tampered = signed.sub("1234567890", "9999999999")
      result = described_class.verify(tampered)
      expect(result).not_to be_valid
      expect(result.errors).to include("document digest mismatch")
    end

    it "rejects a modified SignatureValue" do
      # Flip one bit of the decoded signature bytes (guaranteed to change the value, unlike
      # swapping a base64 character, which is a no-op whenever it happens to match already).
      tampered = signed.sub(%r{(<ds:SignatureValue[^>]*>)([^<]+)(</ds:SignatureValue>)}) do
        pre = Regexp.last_match(1)
        encoded = Regexp.last_match(2)
        post = Regexp.last_match(3)
        bytes = Base64.decode64(encoded)
        bytes[0] = (bytes[0].ord ^ 0xFF).chr
        "#{pre}#{Base64.strict_encode64(bytes)}#{post}"
      end
      result = described_class.verify(tampered)
      expect(result).not_to be_valid
      expect(result.errors).to include("signature does not match certificate")
    end

    it "rejects a document with no signature at all" do
      result = described_class.verify(xml)
      expect(result).not_to be_valid
    end

    it "rejects signing when given an object with no root element" do
      expect { described_class.sign("", certificate: build_rsa_certificate) }.to raise_error(Xades::MalformedDocumentError)
    end
  end

  describe ".verify!" do
    it "returns true for a valid signature" do
      signed = described_class.sign(xml, certificate: build_rsa_certificate)
      expect(described_class.verify!(signed)).to be true
    end

    it "raises Xades::VerificationError, with the Result's errors joined into the message, for an invalid one" do
      expect { described_class.verify!(xml) }.to raise_error(Xades::VerificationError, /no Signature element found/)
    end
  end
end
