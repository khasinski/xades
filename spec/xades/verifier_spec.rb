# frozen_string_literal: true

# Builds a minimal, valid XAdES-BES document by hand (independent of Xades::Signer, which only
# ever produces SHA-256/RSA-SHA256|ECDSA-SHA256) so we can prove Verifier genuinely supports the
# other algorithm combinations KSeF's docs list, not just parse them.
RSpec.describe Xades::Verifier do
  def build_document(key:, cert:, signature_method:, digest_uri:)
    xml = '<Root xmlns="urn:test"><Payload>hello</Payload></Root>'
    doc = Nokogiri::XML(xml)
    document_digest = Xades::Digest.base64(Xades::C14N.canonicalize(doc.root), digest_uri)

    signed_properties = <<~XML.strip
      <xades:SignedProperties xmlns:xades="#{Xades::Algorithms::XADES_NAMESPACE}" Id="sp-1"><xades:SignedSignatureProperties><xades:SigningTime>2026-01-01T00:00:00Z</xades:SigningTime></xades:SignedSignatureProperties></xades:SignedProperties>
    XML
    signed_properties_digest = Xades::Digest.base64(Xades::C14N.canonicalize(Nokogiri::XML(signed_properties).root), digest_uri)

    signed_info = <<~XML.strip
      <ds:SignedInfo xmlns:ds="#{Xades::Algorithms::DS_NAMESPACE}"><ds:CanonicalizationMethod Algorithm="#{Xades::Algorithms::C14N_EXCLUSIVE}"/><ds:SignatureMethod Algorithm="#{signature_method}"/><ds:Reference URI=""><ds:Transforms><ds:Transform Algorithm="#{Xades::Algorithms::ENVELOPED_SIGNATURE}"/><ds:Transform Algorithm="#{Xades::Algorithms::C14N_EXCLUSIVE}"/></ds:Transforms><ds:DigestMethod Algorithm="#{digest_uri}"/><ds:DigestValue>#{document_digest}</ds:DigestValue></ds:Reference><ds:Reference Type="#{Xades::Algorithms::XADES_SIGNED_PROPERTIES_TYPE}" URI="#sp-1"><ds:Transforms><ds:Transform Algorithm="#{Xades::Algorithms::C14N_EXCLUSIVE}"/></ds:Transforms><ds:DigestMethod Algorithm="#{digest_uri}"/><ds:DigestValue>#{signed_properties_digest}</ds:DigestValue></ds:Reference></ds:SignedInfo>
    XML
    bytes_to_sign = Xades::C14N.canonicalize(Nokogiri::XML(signed_info).root)

    algorithm = Xades::Algorithms::SIGNATURE_METHODS.fetch(signature_method)
    raw_der = key.sign(OpenSSL::Digest.new(algorithm[:digest]), bytes_to_sign)
    signature_value = if algorithm[:key_type] == :ecdsa
                        Base64.strict_encode64(Xades::EcdsaSignature.der_to_raw(raw_der, Xades::EcdsaSignature.field_bytes_for(key)))
                      else
                        Base64.strict_encode64(raw_der)
                      end

    skeleton = <<~XML.strip
      <ds:Signature xmlns:ds="#{Xades::Algorithms::DS_NAMESPACE}" Id="sig-1">#{signed_info}<ds:SignatureValue>#{signature_value}</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>#{Base64.strict_encode64(cert.to_der)}</ds:X509Certificate></ds:X509Data></ds:KeyInfo><ds:Object><xades:QualifyingProperties xmlns:xades="#{Xades::Algorithms::XADES_NAMESPACE}" Target="#sig-1">#{signed_properties}</xades:QualifyingProperties></ds:Object></ds:Signature>
    XML
    doc.root.add_child(doc.fragment(skeleton))
    doc.to_xml(save_with: Nokogiri::XML::Node::SaveOptions::AS_XML)
  end

  def self_signed_cert_for(key)
    cert = OpenSSL::X509::Certificate.new
    cert.serial = 1
    cert.subject = OpenSSL::X509::Name.parse("/CN=Test")
    cert.issuer = cert.subject
    cert.public_key = key.is_a?(OpenSSL::PKey::EC) ? key : key.public_key
    cert.not_before = Time.now
    cert.not_after = Time.now + 3600
    cert.sign(key, OpenSSL::Digest.new("SHA256"))
    cert
  end

  describe "signature method / digest algorithm combinations KSeF's docs list" do
    let(:rsa_key) { OpenSSL::PKey::RSA.generate(2048) }
    let(:rsa_cert) { self_signed_cert_for(rsa_key) }
    let(:ec_key) { OpenSSL::PKey::EC.generate("prime256v1") }
    let(:ec_cert) { self_signed_cert_for(ec_key) }

    {
      "http://www.w3.org/2000/09/xmldsig#rsa-sha1" => "http://www.w3.org/2000/09/xmldsig#sha1",
      "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" => "http://www.w3.org/2001/04/xmlenc#sha256",
      "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384" => "http://www.w3.org/2001/04/xmldsig-more#sha384",
      "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512" => "http://www.w3.org/2001/04/xmlenc#sha512"
    }.each do |signature_method, digest_uri|
      it "verifies RSA #{signature_method.split("#").last}" do
        document = build_document(key: rsa_key, cert: rsa_cert, signature_method: signature_method, digest_uri: digest_uri)
        expect(described_class.verify(document)).to be_valid
      end
    end

    {
      "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1" => "http://www.w3.org/2000/09/xmldsig#sha1",
      "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256" => "http://www.w3.org/2001/04/xmlenc#sha256",
      "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384" => "http://www.w3.org/2001/04/xmldsig-more#sha384",
      "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512" => "http://www.w3.org/2001/04/xmlenc#sha512"
    }.each do |signature_method, digest_uri|
      it "verifies ECDSA #{signature_method.split("#").last}" do
        document = build_document(key: ec_key, cert: ec_cert, signature_method: signature_method, digest_uri: digest_uri)
        expect(described_class.verify(document)).to be_valid
      end
    end

    it "rejects a completely unknown SignatureMethod" do
      document = build_document(
        key: rsa_key, cert: rsa_cert,
        signature_method: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", digest_uri: "http://www.w3.org/2001/04/xmlenc#sha256"
      ).sub("rsa-sha256", "rsa-made-up")
      result = described_class.verify(document)
      expect(result).not_to be_valid
      expect(result.errors).to include(a_string_matching(/unsupported SignatureMethod/))
    end
  end

  describe "malformed input" do
    it "reports no Signature element found for a document with none" do
      result = described_class.verify("<Root/>")
      expect(result).not_to be_valid
      expect(result.errors).to eq(["no Signature element found"])
    end

    it "reports no SignedInfo element found when Signature has none" do
      xml = '<Root xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:Signature/></Root>'
      result = described_class.verify(xml)
      expect(result).not_to be_valid
      expect(result.errors).to eq(["no SignedInfo element found"])
    end
  end

  describe ".verify!" do
    it "returns true instead of a Result when valid" do
      document = build_document(
        key: (key = OpenSSL::PKey::RSA.generate(2048)), cert: self_signed_cert_for(key),
        signature_method: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", digest_uri: "http://www.w3.org/2001/04/xmlenc#sha256"
      )
      expect(described_class.verify!(document)).to be true
    end

    it "raises Xades::VerificationError joining every Result error into the message" do
      expect { described_class.verify!("<Root/>") }.to raise_error(Xades::VerificationError, "XAdES signature is invalid: no Signature element found")
    end
  end
end
