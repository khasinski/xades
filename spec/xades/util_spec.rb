# frozen_string_literal: true

RSpec.describe Xades::Util do
  describe ".escape_xml_text" do
    it "escapes &, < and > but leaves quotes alone (this is element text, not an attribute)" do
      expect(described_class.escape_xml_text(%(a & b < c > d "e" 'f'))).to eq(%(a &amp; b &lt; c &gt; d "e" 'f'))
    end

    it "escapes & before < and > so it never double-escapes the entities it just introduced" do
      expect(described_class.escape_xml_text("<>")).to eq("&lt;&gt;")
    end

    it "round-trips through Nokogiri as the original text" do
      original = "CN=Alice & Bob <Corp>, O=A>B"
      escaped = described_class.escape_xml_text(original)
      doc = Nokogiri::XML("<x>#{escaped}</x>")
      expect(doc.at_xpath("//x").text).to eq(original)
    end

    it "handles nil and non-string input by stringifying first" do
      expect(described_class.escape_xml_text(nil)).to eq("")
      expect(described_class.escape_xml_text(42)).to eq("42")
    end
  end

  describe ".random_id" do
    it "prefixes the given string" do
      expect(described_class.random_id("foo")).to start_with("foo-")
    end

    it "is unique across calls" do
      ids = Array.new(1000) { described_class.random_id("x") }
      expect(ids.uniq.size).to eq(1000)
    end

    it "is safe to use as an XML ID (NCName: no special characters)" do
      id = described_class.random_id("prefix")
      expect(id).to match(/\A[A-Za-z][A-Za-z0-9-]*\z/)
    end
  end
end
