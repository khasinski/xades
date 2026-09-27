# frozen_string_literal: true

require "date"

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

    describe "signing_time normalization" do
      it "accepts a Time as-is" do
        signed = described_class.new(certificate: certificate, signing_time: Time.utc(2026, 4, 1, 9)).sign(xml)
        expect(Nokogiri::XML(signed).at_xpath("//*[local-name()='SigningTime']").text).to eq("2026-04-01T09:00:00Z")
      end

      it "converts a DateTime via #to_time (bare DateTime has no #utc and would otherwise raise NoMethodError)" do
        signed = described_class.new(certificate: certificate, signing_time: DateTime.new(2026, 4, 1, 9)).sign(xml)
        expect(Nokogiri::XML(signed).at_xpath("//*[local-name()='SigningTime']").text).to eq("2026-04-01T09:00:00Z")
      end

      it "converts a Date via #to_time" do
        expect { described_class.new(certificate: certificate, signing_time: Date.new(2026, 4, 1)).sign(xml) }.not_to raise_error
      end

      it "raises a clear ArgumentError for something with neither #utc nor #to_time, instead of a bare NoMethodError" do
        expect do
          described_class.new(certificate: certificate, signing_time: "2026-04-01").sign(xml)
        end.to raise_error(ArgumentError, /signing_time must be a Time/)
      end
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

    describe "certificate validity period" do
      it "raises CertificateValidityError when signing_time is before the certificate's not_before" do
        expect do
          described_class.new(certificate: certificate, signing_time: certificate.x509.not_before - 1).sign(xml)
        end.to raise_error(Xades::CertificateValidityError, /not yet valid/)
      end

      it "raises CertificateValidityError when signing_time is after the certificate's not_after" do
        expect do
          described_class.new(certificate: certificate, signing_time: certificate.x509.not_after + 1).sign(xml)
        end.to raise_error(Xades::CertificateValidityError, /expired/)
      end

      it "does not raise when signing_time is within the certificate's validity period" do
        expect do
          described_class.new(certificate: certificate, signing_time: certificate.x509.not_before + 1).sign(xml)
        end.not_to raise_error
      end

      it "can be bypassed with allow_invalid_certificate_period: true" do
        expect do
          described_class.new(
            certificate: certificate,
            signing_time: certificate.x509.not_after + 1,
            allow_invalid_certificate_period: true
          ).sign(xml)
        end.not_to raise_error
      end
    end
  end
end
