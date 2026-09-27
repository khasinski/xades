# frozen_string_literal: true

module Xades
  module Builder
    # Builds <ds:SignedInfo>: the two References required by XAdES-BASELINE-B (the enveloped
    # document, and the SignedProperties) plus the canonicalization/signature method declarations.
    module SignedInfo
      def self.build(signature_method:, document_digest:, document_reference_id:, signed_properties_id:,
                     signed_properties_digest:)
        <<~XML.strip
          <ds:SignedInfo xmlns:ds="#{Algorithms::DS_NAMESPACE}"><ds:CanonicalizationMethod Algorithm="#{Algorithms::C14N_EXCLUSIVE}"/><ds:SignatureMethod Algorithm="#{signature_method}"/><ds:Reference Id="#{document_reference_id}" URI=""><ds:Transforms><ds:Transform Algorithm="#{Algorithms::ENVELOPED_SIGNATURE}"/><ds:Transform Algorithm="#{Algorithms::C14N_EXCLUSIVE}"/></ds:Transforms><ds:DigestMethod Algorithm="#{Algorithms::DIGEST_SHA256}"/><ds:DigestValue>#{document_digest}</ds:DigestValue></ds:Reference><ds:Reference Type="#{Algorithms::XADES_SIGNED_PROPERTIES_TYPE}" URI="##{signed_properties_id}"><ds:Transforms><ds:Transform Algorithm="#{Algorithms::C14N_EXCLUSIVE}"/></ds:Transforms><ds:DigestMethod Algorithm="#{Algorithms::DIGEST_SHA256}"/><ds:DigestValue>#{signed_properties_digest}</ds:DigestValue></ds:Reference></ds:SignedInfo>
        XML
      end
    end
  end
end
