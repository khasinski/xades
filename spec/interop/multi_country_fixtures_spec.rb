# frozen_string_literal: true

# XAdES-BES is a European standard, not a Polish one -- KSeF is our primary driver, but the same
# gem should verify real signatures from other EU countries too. These fixtures are ordinary valid
# signatures from other tools/ETSI plugtests (see SOURCES.md); each positive one here caught a real
# interop bug during development (hardcoded Exclusive C14N, wrong Reference picked when several
# untyped ones are present) that a KSeF-only fixture set would never have exercised.
RSpec.describe "multi-country interop fixtures" do
  def verify(filename)
    Xades::Bes.verify(File.read(File.join(File.join(__dir__, "..", "fixtures", "interop"), filename)))
  end

  describe "positive: real signatures from other countries verify as-is" do
    it "Denmark: a plain enveloped signature" do
      expect(verify("dk_tl-sn21.xml")).to be_valid
    end

    it "United Kingdom: SignedProperties Reference has no Transforms (implicit plain C14N 1.0 default)" do
      expect(verify("Signature-X-UK_ASC-2.xml")).to be_valid
    end

    it "Spain (Facturae): RSA-SHA1 signature, three References including one protecting KeyInfo" do
      expect(verify("factura_ejemplo2_32v1.xml")).to be_valid
    end

    it "ETSI plugtest (international): enveloped signature using an XPath filter transform" do
      expect(verify("TEST_S1a_C1a_InTL_VALID.xml")).to be_valid
    end
  end

  describe "documented scope limitation: enveloping (non-enveloped) signatures from other countries" do
    # Same limitation as xades-extended-epes.xml (spec/interop/vendored_fixtures_spec.rb) -- these
    # are genuinely valid signatures, just not in the enveloped shape this gem's Verifier expects.
    { "Slovakia" => "Signature-X-SK_DIT-1.xml", "Hungary" => "Signature-X-HU_POL-3.xml", "Austria" => "X_AT_SIT_1.xml" }.each do |country, file|
      it "#{country}: reports the enveloping limitation rather than silently mis-verifying" do
        result = verify(file)
        expect(result).not_to be_valid
        expect(result.errors).to include("missing document Reference in SignedInfo")
      end
    end
  end
end
