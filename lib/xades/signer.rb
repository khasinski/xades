# frozen_string_literal: true

module Xades
  # Produces an XAdES-BES / BASELINE-B enveloped signature on an XML document.
  #
  # Build order (each step's correctness was verified empirically against Nokogiri/OpenSSL
  # behavior and a real DSS-generated fixture before this was written -- see scratchpad notes):
  #   1. Digest the original document (no Signature present yet == enveloped transform is a no-op).
  #   2. Build the whole <ds:Signature> subtree as a self-contained fragment (its own xmlns:ds /
  #      xmlns:xades declarations) with a placeholder SignedProperties digest and SignatureValue,
  #      and graft it onto the document root.
  #   3. Now that SignedProperties is embedded with real ancestor context, canonicalize it and
  #      patch its real digest into the (still embedded) SignedInfo/Reference.
  #   4. Canonicalize the now-final SignedInfo node -- that's the exact byte sequence signed.
  class Signer
    def initialize(certificate:, signing_time: Time.now.utc, signing_certificate_version: :v2, id_prefix: "xades")
      @certificate = certificate
      @signing_time = signing_time
      @signing_certificate_version = signing_certificate_version
      @id_prefix = id_prefix
    end

    def sign(xml)
      doc = Nokogiri::XML(xml.to_s)
      raise MalformedDocumentError, "document has no root element" unless doc.root

      document_digest = Xades::Digest.sha256_base64(Xades::C14N.canonicalize(doc.root))
      signature_node = doc.root.add_child(doc.fragment(build_skeleton(document_digest)))

      patch_signed_properties_digest!(signature_node)
      patch_signature_value!(signature_node)

      # Nokogiri's default to_xml applies FORMAT (pretty-printing), which inserts new whitespace
      # text nodes on reparse -- and canonicalization treats whitespace as significant, so that
      # would silently invalidate every digest we just computed. AS_XML alone preserves exactly
      # the tree we signed.
      doc.to_xml(save_with: Nokogiri::XML::Node::SaveOptions::AS_XML)
    end

    private

    Ids = Struct.new(:signature, :document_reference, :signed_properties, :key_info, :signature_value)

    def generate_ids
      Ids.new(*%w[signature ref signedprops keyinfo sigvalue].map { |name| Util.random_id("#{@id_prefix}-#{name}") })
    end

    # SignedProperties' real digest isn't known yet at this point (it depends on the certificate
    # and signing time, not the placeholder digest below) -- it's patched in once this skeleton is
    # embedded in the document, see #patch_signed_properties_digest!.
    def build_skeleton(document_digest)
      ids = generate_ids
      parts = {
        signed_info: build_signed_info(ids, document_digest),
        key_info: Builder::KeyInfo.build(certificate: @certificate, id: ids.key_info),
        qualifying_properties: build_qualifying_properties(ids)
      }

      assemble_signature_xml(ids, **parts)
    end

    def build_signed_info(ids, document_digest)
      Builder::SignedInfo.build(
        signature_method: @certificate.ec? ? Algorithms::SIGNATURE_ECDSA_SHA256 : Algorithms::SIGNATURE_RSA_SHA256,
        document_digest: document_digest,
        document_reference_id: ids.document_reference,
        signed_properties_id: ids.signed_properties,
        signed_properties_digest: ""
      )
    end

    def build_qualifying_properties(ids)
      Builder::QualifyingProperties.build(
        certificate: @certificate,
        signature_id: ids.signature,
        signed_properties_id: ids.signed_properties,
        signing_time: @signing_time,
        version: @signing_certificate_version
      )
    end

    def assemble_signature_xml(ids, signed_info:, key_info:, qualifying_properties:)
      <<~XML.strip
        <ds:Signature xmlns:ds="#{Algorithms::DS_NAMESPACE}" Id="#{ids.signature}">#{signed_info}<ds:SignatureValue Id="#{ids.signature_value}"></ds:SignatureValue>#{key_info}<ds:Object>#{qualifying_properties}</ds:Object></ds:Signature>
      XML
    end

    def patch_signed_properties_digest!(signature_node)
      signed_properties_node = signature_node.at_xpath(".//*[local-name()='SignedProperties']")
      digest = Xades::Digest.sha256_base64(Xades::C14N.canonicalize(signed_properties_node))

      digest_value_node = signature_node.at_xpath(
        ".//*[local-name()='Reference'][@Type='#{Algorithms::XADES_SIGNED_PROPERTIES_TYPE}']/*[local-name()='DigestValue']"
      )
      digest_value_node.content = digest
    end

    def patch_signature_value!(signature_node)
      signed_info_node = signature_node.at_xpath("./*[local-name()='SignedInfo']")
      bytes_to_sign = Xades::C14N.canonicalize(signed_info_node)

      signature_value_node = signature_node.at_xpath("./*[local-name()='SignatureValue']")
      signature_value_node.content = compute_signature(bytes_to_sign)
    end

    def compute_signature(bytes)
      digest = OpenSSL::Digest.new("SHA256")
      if @certificate.ec?
        der = @certificate.key.sign(digest, bytes)
        raw = EcdsaSignature.der_to_raw(der, EcdsaSignature.field_bytes_for(@certificate.key))
        Base64.strict_encode64(raw)
      else
        Base64.strict_encode64(@certificate.key.sign(digest, bytes))
      end
    end
  end
end
