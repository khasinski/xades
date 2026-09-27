# frozen_string_literal: true

RSpec.describe Xades::Builder::SignedInfo do
  it "builds the two References BASELINE-B requires, with digests taken from the caller" do
    xml = described_class.build(
      signature_method: Xades::Algorithms::SIGNATURE_RSA_SHA256,
      document_digest: "DOC_DIGEST",
      document_reference_id: "ref-1",
      signed_properties_id: "sp-1",
      signed_properties_digest: "SP_DIGEST"
    )
    doc = Nokogiri::XML(xml)

    expect(doc.at_xpath("//*[local-name()='CanonicalizationMethod']")["Algorithm"]).to eq(Xades::Algorithms::C14N_EXCLUSIVE)
    expect(doc.at_xpath("//*[local-name()='SignatureMethod']")["Algorithm"]).to eq(Xades::Algorithms::SIGNATURE_RSA_SHA256)

    doc_ref = doc.at_xpath("//*[local-name()='Reference'][@Id='ref-1']")
    expect(doc_ref["URI"]).to eq("")
    transforms = doc_ref.xpath(".//*[local-name()='Transform']").map { |t| t["Algorithm"] }
    expect(transforms).to eq([Xades::Algorithms::ENVELOPED_SIGNATURE, Xades::Algorithms::C14N_EXCLUSIVE])
    expect(doc_ref.at_xpath(".//*[local-name()='DigestValue']").text).to eq("DOC_DIGEST")

    sp_ref = doc.at_xpath("//*[local-name()='Reference'][@Type='#{Xades::Algorithms::XADES_SIGNED_PROPERTIES_TYPE}']")
    expect(sp_ref["URI"]).to eq("#sp-1")
    expect(sp_ref.at_xpath(".//*[local-name()='DigestValue']").text).to eq("SP_DIGEST")
  end
end
