# frozen_string_literal: true

RSpec.describe Xades::C14N do
  let(:doc) { Nokogiri::XML('<root xmlns="urn:test"><child>value</child></root>') }

  describe ".canonicalize" do
    it "defaults to Exclusive C14N" do
      expect(described_class.canonicalize(doc.root)).to eq(
        described_class.canonicalize(doc.root, Xades::Algorithms::C14N_EXCLUSIVE)
      )
    end

    it "supports plain C14N 1.0" do
      result = described_class.canonicalize(doc.root, Xades::Algorithms::C14N_1_0)
      expect(result).to be_a(String)
    end

    it "supports C14N 1.1" do
      result = described_class.canonicalize(doc.root, Xades::Algorithms::C14N_1_1)
      expect(result).to be_a(String)
    end

    it "raises Xades::UnsupportedAlgorithmError for an unknown algorithm" do
      expect do
        described_class.canonicalize(doc.root, "urn:not-a-real-c14n-algorithm")
      end.to raise_error(Xades::UnsupportedAlgorithmError, /not-a-real-c14n-algorithm/)
    end

    it "produces different output for exclusive vs plain C14N when an unused ancestor namespace is in scope" do
      wrapper = Nokogiri::XML('<a xmlns:unused="urn:unused"><b xmlns="urn:test"><c/></b></a>')
      node = wrapper.at_xpath("//*[local-name()='b']")

      exclusive = described_class.canonicalize(node, Xades::Algorithms::C14N_EXCLUSIVE)
      plain = described_class.canonicalize(node, Xades::Algorithms::C14N_1_0)

      expect(exclusive).not_to include("unused")
      expect(plain).to include("unused")
    end
  end

  describe ".supported?" do
    it "is true for the three algorithms this gem knows" do
      expect(described_class.supported?(Xades::Algorithms::C14N_EXCLUSIVE)).to be true
      expect(described_class.supported?(Xades::Algorithms::C14N_1_0)).to be true
      expect(described_class.supported?(Xades::Algorithms::C14N_1_1)).to be true
    end

    it "is false for an unknown URI" do
      expect(described_class.supported?("urn:nope")).to be false
    end
  end
end
