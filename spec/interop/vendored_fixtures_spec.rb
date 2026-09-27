# frozen_string_literal: true

# Verifies Xades::Bes.verify against real-world XAdES documents vendored from other
# implementations' test suites (see spec/fixtures/interop/SOURCES.md for provenance/licenses),
# rather than only round-tripping documents we produced ourselves.
RSpec.describe "vendored interop fixtures" do
  fixtures_dir = File.join(__dir__, "..", "fixtures", "interop")

  def verify(filename)
    Xades::Bes.verify(File.read(File.join(File.join(__dir__, "..", "fixtures", "interop"), filename)))
  end

  it "accepts a real DSS-generated, RSA-signed, enveloped XAdES-BASELINE-B signature" do
    result = verify("dss-signed.xml")
    expect(result).to be_valid
  end

  it "rejects a document whose SignedProperties/Reference was stripped after signing" do
    result = verify("dss-signed-altered-signedPropsRemoved.xml")
    expect(result).not_to be_valid
  end

  it "rejects a document whose main document Reference was removed after signing" do
    result = verify("nonconformant-dss-signed-altered-refRemoved.xml")
    expect(result).not_to be_valid
  end

  it "rejects a SigningCertificate (V1) whose CertDigest doesn't match the embedded certificate" do
    result = verify("xades-wrong-sign-cert-digest.xml")
    expect(result).not_to be_valid
    expect(result.errors).to include("SigningCertificate digest does not match the embedded certificate")
  end

  it "rejects a SigningCertificateV2 whose CertDigest doesn't match the embedded certificate" do
    result = verify("xades-sign-cert-v2-wrong-digest.xml")
    expect(result).not_to be_valid
    expect(result.errors).to include("SigningCertificate digest does not match the embedded certificate")
  end

  it "rejects an IssuerSerialV2 that doesn't match the embedded certificate's issuer/serial" do
    result = verify("xades-sign-cert-v2-wrong-issuer-serial.xml")
    expect(result).not_to be_valid
    expect(result.errors).to include("IssuerSerialV2 does not match the embedded certificate's issuer/serial")
  end

  it "documents a known scope limitation: enveloping (non-enveloped) signatures aren't understood" do
    # xades-extended-epes.xml is a genuinely valid XAdES-EPES signature -- just not in the
    # enveloped, URI="" shape this gem's Verifier looks for. See README "Limitations".
    result = verify("xades-extended-epes.xml")
    expect(result).not_to be_valid
    expect(result.errors).to include("missing document Reference in SignedInfo")
  end

  it "lists every fixture file in SOURCES.md" do
    documented = File.read(File.join(fixtures_dir, "SOURCES.md"))
    Dir.glob(File.join(fixtures_dir, "*.xml")).each do |path|
      expect(documented).to include(File.basename(path))
    end
  end
end
