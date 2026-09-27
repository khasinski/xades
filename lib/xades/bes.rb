# frozen_string_literal: true

module Xades
  # Public entry point: XAdES-BES / BASELINE-B signing and verification.
  #
  #   certificate = Xades::Certificate.from_pem(cert: File.read("cert.pem"), key: File.read("key.pem"))
  #   signed_xml  = Xades::Bes.sign(xml, certificate: certificate)
  #   result      = Xades::Bes.verify(signed_xml)
  #   result.valid? # => true
  module Bes
    def self.sign(xml, certificate:, signing_time: Time.now.utc, signing_certificate_version: :v2)
      Signer.new(
        certificate: certificate,
        signing_time: signing_time,
        signing_certificate_version: signing_certificate_version
      ).sign(xml)
    end

    def self.verify(xml)
      Verifier.verify(xml)
    end
  end
end
