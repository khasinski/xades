# frozen_string_literal: true

module Xades
  # Wraps Nokogiri's native Exclusive XML Canonicalization (C14N 1.0, no comments),
  # the only canonicalization method KSeF / ETSI XAdES-BASELINE-B require.
  module C14N
    MODE = Nokogiri::XML::XML_C14N_EXCLUSIVE_1_0

    def self.canonicalize(node)
      node.canonicalize(MODE)
    end
  end
end
