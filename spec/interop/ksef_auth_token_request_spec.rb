# frozen_string_literal: true

# The golden fixture: signing KSeF 2.0's AuthTokenRequest, the actual driver for this gem (see
# README). Built against the official schema (CIRFMF/ksef-docs auth/schemy/schemat_auth_v2-1.xsd,
# namespace http://ksef.mf.gov.pl/auth/token/2.1) and the documented XAdES parameter constraints
# (CIRFMF/ksef-docs auth/podpis-xades.md): enveloped or enveloping only (never detached), exc-c14n,
# RSA-SHA256/ECDSA-SHA256 with SHA-256 digests, ECDSA as raw R||S per RFC 4050.
#
# This does not call the real KSeF API (that needs network access and real/test credentials --
# out of scope for a unit suite); it checks our output against the documented requirements instead.
RSpec.describe "KSeF AuthTokenRequest golden fixture" do
  let(:nip) { "1234567890" }
  let(:challenge) { "20260401-CR-0123456789-ABCDEF0123-01" }
  let(:auth_token_request) do
    <<~XML.strip
      <AuthTokenRequest xmlns="http://ksef.mf.gov.pl/auth/token/2.1"><Challenge>#{challenge}</Challenge><ContextIdentifier><Nip>#{nip}</Nip></ContextIdentifier><SubjectIdentifierType>certificateSubject</SubjectIdentifierType></AuthTokenRequest>
    XML
  end

  # KSeF's own Challenge pattern, so a fixture drift (e.g. wrong NIP length) fails loudly here
  # rather than surfacing as a confusing signature failure against the real API.
  it "the fixture itself matches the published AuthTokenRequest schema constraints" do
    expect(challenge).to match(/\A\d{8}-CR-[A-F0-9]{10}-[A-F0-9]{10}-[A-F0-9]{2}\z/)
    expect(nip).to match(/\A[1-9]((\d[1-9])|([1-9]\d))\d{7}\z/)
  end

  shared_examples "a KSeF-conformant AuthTokenRequest signature" do
    it "verifies" do
      expect(Xades::Bes.verify(signed)).to be_valid
    end

    it "preserves the AuthTokenRequest as the enveloped document (schema-valid root untouched)" do
      doc = Nokogiri::XML(signed)
      expect(doc.root.name).to eq("AuthTokenRequest")
      expect(doc.at_xpath("//*[local-name()='Challenge']").text).to eq(challenge)
      expect(doc.at_xpath("//*[local-name()='Nip']").text).to eq(nip)
    end

    it "uses Exclusive C14N (one of KSeF's accepted canonicalization methods)" do
      doc = Nokogiri::XML(signed)
      expect(doc.at_xpath("//*[local-name()='CanonicalizationMethod']")["Algorithm"]).to eq(Xades::Algorithms::C14N_EXCLUSIVE)
    end

    it "uses only SHA-256 digests throughout (KSeF-accepted)" do
      doc = Nokogiri::XML(signed)
      doc.xpath("//*[local-name()='DigestMethod']").each do |dm|
        expect(dm["Algorithm"]).to eq(Xades::Algorithms::DIGEST_SHA256)
      end
    end
  end

  context "with an RSA certificate (2048-bit minimum, per KSeF docs)" do
    let(:certificate) { build_rsa_certificate }
    let(:signed) { Xades::Bes.sign(auth_token_request, certificate: certificate) }

    include_examples "a KSeF-conformant AuthTokenRequest signature"

    it "signs with rsa-sha256 and a >= 2048-bit key" do
      doc = Nokogiri::XML(signed)
      expect(doc.at_xpath("//*[local-name()='SignatureMethod']")["Algorithm"]).to eq(Xades::Algorithms::SIGNATURE_RSA_SHA256)
      expect(certificate.key.n.num_bits).to be >= 2048
    end
  end

  context "with an EC certificate (P-256 minimum, per KSeF docs)" do
    let(:certificate) { build_ec_certificate(curve: "prime256v1") }
    let(:signed) { Xades::Bes.sign(auth_token_request, certificate: certificate) }

    include_examples "a KSeF-conformant AuthTokenRequest signature"

    it "signs with ecdsa-sha256 and encodes SignatureValue as raw R||S (RFC 4050), not DER" do
      doc = Nokogiri::XML(signed)
      expect(doc.at_xpath("//*[local-name()='SignatureMethod']")["Algorithm"]).to eq(Xades::Algorithms::SIGNATURE_ECDSA_SHA256)

      raw_signature = Base64.decode64(doc.at_xpath("//*[local-name()='SignatureValue']").text)
      expect(raw_signature.bytesize).to eq(64) # 2 * 32 bytes for P-256 -- would be a DER SEQUENCE (variable-length) otherwise
      expect { OpenSSL::ASN1.decode(raw_signature) }.to raise_error(OpenSSL::ASN1::ASN1Error)
    end
  end
end
