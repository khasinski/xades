# frozen_string_literal: true

module Xades
  module Algorithms
    DS_NAMESPACE = "http://www.w3.org/2000/09/xmldsig#"
    XADES_NAMESPACE = "http://uri.etsi.org/01903/v1.3.2#"
    XADES_SIGNED_PROPERTIES_TYPE = "http://uri.etsi.org/01903#SignedProperties"

    C14N_EXCLUSIVE = "http://www.w3.org/2001/10/xml-exc-c14n#"
    C14N_1_0 = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
    C14N_1_1 = "http://www.w3.org/2006/12/xml-c14n11"
    ENVELOPED_SIGNATURE = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"

    DIGEST_SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"

    SIGNATURE_RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
    SIGNATURE_ECDSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"

    # This gem always *signs* with RSA/ECDSA-SHA256, but a document we *verify* may legally use
    # any of these (KSeF's own docs list all of them; RSA-PSS and SHA-3 variants are not yet
    # supported -- see README limitations).
    SIGNATURE_METHODS = {
      "http://www.w3.org/2000/09/xmldsig#rsa-sha1" => { key_type: :rsa, digest: "SHA1" },
      SIGNATURE_RSA_SHA256 => { key_type: :rsa, digest: "SHA256" },
      "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384" => { key_type: :rsa, digest: "SHA384" },
      "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512" => { key_type: :rsa, digest: "SHA512" },
      "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1" => { key_type: :ecdsa, digest: "SHA1" },
      SIGNATURE_ECDSA_SHA256 => { key_type: :ecdsa, digest: "SHA256" },
      "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384" => { key_type: :ecdsa, digest: "SHA384" },
      "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512" => { key_type: :ecdsa, digest: "SHA512" }
    }.freeze
  end
end
