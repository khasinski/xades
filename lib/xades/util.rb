# frozen_string_literal: true

module Xades
  # @api private
  module Util
    module_function

    # Escapes text for use inside XML element content (not attribute values).
    def escape_xml_text(str)
      str.to_s.gsub("&", "&amp;").gsub("<", "&lt;").gsub(">", "&gt;")
    end

    def random_id(prefix)
      "#{prefix}-#{SecureRandom.hex(16)}"
    end
  end
end
