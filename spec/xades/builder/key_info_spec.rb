# frozen_string_literal: true

RSpec.describe Xades::Builder::KeyInfo do
  let(:certificate) { build_rsa_certificate }

  it "builds a self-contained ds:KeyInfo/X509Data/X509Certificate fragment" do
    xml = described_class.build(certificate: certificate, id: "KeyInfo-1")
    doc = Nokogiri::XML(xml)

    key_info = doc.root
    expect(key_info.name).to eq("KeyInfo")
    expect(key_info.namespace.href).to eq(Xades::Algorithms::DS_NAMESPACE)
    expect(key_info["Id"]).to eq("KeyInfo-1")

    cert_node = key_info.at_xpath(".//*[local-name()='X509Certificate']")
    expect(Base64.decode64(cert_node.text)).to eq(certificate.x509.to_der)
  end
end
