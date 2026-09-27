# frozen_string_literal: true

RSpec.describe Xades::EcdsaSignature do
  describe ".field_bytes_for" do
    it "knows the field width of each supported curve" do
      expect(described_class.field_bytes_for(OpenSSL::PKey::EC.generate("prime256v1"))).to eq(32)
      expect(described_class.field_bytes_for(OpenSSL::PKey::EC.generate("secp384r1"))).to eq(48)
      expect(described_class.field_bytes_for(OpenSSL::PKey::EC.generate("secp521r1"))).to eq(66)
    end

    it "raises for unsupported curves" do
      expect do
        described_class.field_bytes_for(OpenSSL::PKey::EC.generate("secp256k1"))
      end.to raise_error(Xades::UnsupportedKeyError, /secp256k1/)
    end
  end

  describe ".der_to_raw and .raw_to_der" do
    %w[prime256v1 secp384r1 secp521r1].each do |curve|
      it "round-trips DER <-> raw r||s for #{curve} and stays verifiable" do
        key = OpenSSL::PKey::EC.generate(curve)
        byte_len = described_class.field_bytes_for(key)
        data = "the quick brown fox"

        der = key.sign(OpenSSL::Digest.new("SHA256"), data)
        raw = described_class.der_to_raw(der, byte_len)

        expect(raw.bytesize).to eq(byte_len * 2)

        reconstructed_der = described_class.raw_to_der(raw, byte_len)

        expect(key.verify(OpenSSL::Digest.new("SHA256"), reconstructed_der, data)).to be true
      end
    end

    it "correctly pads values with a leading zero byte (small r or s)" do
      # Regression guard: r/s occasionally serialize shorter than the field width and must be
      # zero-padded, not left short -- run enough signatures to hit that case with high probability.
      key = OpenSSL::PKey::EC.generate("prime256v1")
      byte_len = described_class.field_bytes_for(key)

      200.times do |i|
        der = key.sign(OpenSSL::Digest.new("SHA256"), "message #{i}")
        raw = described_class.der_to_raw(der, byte_len)
        expect(raw.bytesize).to eq(byte_len * 2)
        expect(key.verify(OpenSSL::Digest.new("SHA256"), described_class.raw_to_der(raw, byte_len),
                          "message #{i}")).to be true
      end
    end

    it "raises MalformedDocumentError for a raw signature of the wrong length" do
      expect do
        described_class.raw_to_der("short", 32)
      end.to raise_error(Xades::MalformedDocumentError)
    end
  end
end
