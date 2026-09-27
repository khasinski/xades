# frozen_string_literal: true

# Structural conformance checks for XAdES-BASELINE-B (ETSI EN 319 132-1 clause 6.3), mirroring the
# "requirements" test pattern used by esig/dss (dss-xades/src/test/java/.../requirements/
# XAdESBaselineBTest.java): assert exactly what must/must not be present at this level, as opposed
# to a mere round-trip check.
RSpec.describe "XAdES-BASELINE-B structural requirements" do
  subject(:doc) { Nokogiri::XML(Xades::Bes.sign(xml, certificate: certificate)) }

  let(:xml) { '<Root xmlns="urn:test"><Payload>hello</Payload></Root>' }
  let(:certificate) { build_rsa_certificate }

  def find(xpath)
    doc.xpath("//*[local-name()='#{xpath}']")
  end

  it "has exactly one ds:Signature" do
    expect(find("Signature").size).to eq(1)
  end

  it "has exactly one ds:SignedInfo with exactly two ds:Reference elements" do
    expect(find("SignedInfo").size).to eq(1)
    expect(find("Reference").size).to eq(2)
  end

  it "uses Exclusive C14N as SignedInfo's CanonicalizationMethod" do
    expect(find("CanonicalizationMethod").first["Algorithm"]).to eq(Xades::Algorithms::C14N_EXCLUSIVE)
  end

  it "uses a SHA-256 DigestMethod on every Reference" do
    find("Reference").each do |ref|
      expect(ref.at_xpath(".//*[local-name()='DigestMethod']")["Algorithm"]).to eq(Xades::Algorithms::DIGEST_SHA256)
    end
  end

  it "signs with an algorithm in {RSA-SHA256, ECDSA-SHA256}" do
    expect([Xades::Algorithms::SIGNATURE_RSA_SHA256, Xades::Algorithms::SIGNATURE_ECDSA_SHA256])
      .to include(find("SignatureMethod").first["Algorithm"])
  end

  it "has exactly one ds:KeyInfo containing an X.509 certificate" do
    expect(find("KeyInfo").size).to eq(1)
    expect(find("X509Certificate").size).to eq(1)
  end

  it "has exactly one xades:SignedProperties with exactly one SigningTime and one SigningCertificate(V2)" do
    expect(find("SignedProperties").size).to eq(1)
    expect(find("SigningTime").size).to eq(1)
    expect(find("SigningCertificate").size + find("SigningCertificateV2").size).to eq(1)
  end

  it "points QualifyingProperties/@Target at the enclosing Signature's Id" do
    signature_id = find("Signature").first["Id"]
    expect(find("QualifyingProperties").first["Target"]).to eq("##{signature_id}")
  end

  it "the Reference over the document uses the enveloped-signature transform" do
    document_reference = find("Reference").find { |r| r["Type"].nil? }
    algorithms = document_reference.xpath(".//*[local-name()='Transform']").map { |t| t["Algorithm"] }
    expect(algorithms).to include(Xades::Algorithms::ENVELOPED_SIGNATURE)
  end

  it "does NOT include BASELINE-T/-LT/-LTA-only elements (this gem only implements -B)" do
    %w[SignatureTimeStamp CompleteCertificateRefs CompleteRevocationRefs CertificateValues RevocationValues
       ArchiveTimeStamp].each do |el|
      expect(find(el)).to be_empty, "expected no #{el} at BASELINE-B level"
    end
  end
end
