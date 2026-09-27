# frozen_string_literal: true

module Xades
  # Wraps Nokogiri's native XML canonicalization. This gem always *signs* with Exclusive C14N
  # (the mode KSeF and modern XAdES-BASELINE-B generators use), but real-world documents we may
  # need to *verify* can legally declare plain C14N 1.0 or C14N 1.1 instead (KSeF's own docs list
  # all three as acceptable) -- callers that verify third-party documents should pass the
  # algorithm URI actually declared in that document, not assume Exclusive C14N.
  module C14N
    MODES = {
      Algorithms::C14N_EXCLUSIVE => Nokogiri::XML::XML_C14N_EXCLUSIVE_1_0,
      Algorithms::C14N_1_0 => Nokogiri::XML::XML_C14N_1_0,
      Algorithms::C14N_1_1 => Nokogiri::XML::XML_C14N_1_1
    }.freeze

    def self.canonicalize(node, algorithm_uri = Algorithms::C14N_EXCLUSIVE)
      mode = MODES.fetch(algorithm_uri) do
        raise UnsupportedAlgorithmError, "Unsupported canonicalization algorithm: #{algorithm_uri.inspect}"
      end
      node.canonicalize(mode)
    end

    def self.supported?(algorithm_uri)
      MODES.key?(algorithm_uri)
    end
  end
end
