# frozen_string_literal: true

module Xades
  module Builder
    # Builds <ds:KeyInfo><ds:X509Data><ds:X509Certificate>.
    module KeyInfo
      def self.build(certificate:, id:)
        <<~XML.strip
          <ds:KeyInfo xmlns:ds="#{Algorithms::DS_NAMESPACE}" Id="#{id}"><ds:X509Data><ds:X509Certificate>#{certificate.base64_der}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
        XML
      end
    end
  end
end
