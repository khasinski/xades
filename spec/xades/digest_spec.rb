# frozen_string_literal: true

RSpec.describe Xades::Digest do
  describe ".sha256_base64" do
    it "matches an independently computed SHA-256 digest" do
      expect(Base64.decode64(described_class.sha256_base64("hello"))).to eq(OpenSSL::Digest.digest("SHA256", "hello"))
    end
  end

  describe ".base64" do
    {
      "http://www.w3.org/2000/09/xmldsig#sha1" => OpenSSL::Digest::SHA1,
      "http://www.w3.org/2001/04/xmlenc#sha256" => OpenSSL::Digest::SHA256,
      "http://www.w3.org/2001/04/xmldsig-more#sha384" => OpenSSL::Digest::SHA384,
      "http://www.w3.org/2001/04/xmlenc#sha512" => OpenSSL::Digest::SHA512
    }.each do |uri, digest_class|
      it "computes #{digest_class} for #{uri}" do
        expect(Base64.decode64(described_class.base64("data", uri))).to eq(digest_class.digest("data"))
      end
    end

    it "raises Xades::UnsupportedAlgorithmError for an unknown digest URI" do
      expect do
        described_class.base64("data", "urn:not-a-real-digest")
      end.to raise_error(Xades::UnsupportedAlgorithmError, /not-a-real-digest/)
    end
  end

  describe ".supported?" do
    it "is true for known algorithms and false otherwise" do
      expect(described_class.supported?("http://www.w3.org/2001/04/xmlenc#sha256")).to be true
      expect(described_class.supported?("urn:nope")).to be false
    end
  end
end
