# frozen_string_literal: true

module Xades
  module Algorithms
    DS_NAMESPACE = "http://www.w3.org/2000/09/xmldsig#"
    XADES_NAMESPACE = "http://uri.etsi.org/01903/v1.3.2#"
    XADES_SIGNED_PROPERTIES_TYPE = "http://uri.etsi.org/01903#SignedProperties"

    C14N_EXCLUSIVE = "http://www.w3.org/2001/10/xml-exc-c14n#"
    ENVELOPED_SIGNATURE = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"

    DIGEST_SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"

    SIGNATURE_RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
    SIGNATURE_ECDSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
  end
end
