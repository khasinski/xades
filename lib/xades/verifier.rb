# frozen_string_literal: true

module Xades
  # Verifies the structural and cryptographic correctness of an XAdES-BES signature: that the
  # document/SignedProperties digests match and that SignatureValue matches SignedInfo under the
  # embedded certificate's public key.
  #
  # Unlike Signer (which always produces Exclusive C14N / SHA-256 / RSA-SHA256|ECDSA-SHA256, the
  # combination KSeF and modern generators use), Verifier reads and respects whatever
  # canonicalization, digest and signature algorithms a document actually declares -- KSeF's own
  # docs, and real-world signatures from other EU countries, allow several of each. See README.
  #
  # This does NOT validate certificate trust, chain, revocation or validity period -- that is a
  # separate concern (deliberately out of scope for BES-level verification; see the gem's README).
  class Verifier
    Result = Struct.new(:valid, :errors) do
      def valid?
        valid
      end
    end

    def self.verify(xml)
      new(xml).verify
    end

    def initialize(xml)
      @doc = Nokogiri::XML(xml.to_s)
    end

    def verify
      errors = []

      signature_node = @doc.at_xpath("//*[local-name()='Signature']")
      return failure("no Signature element found") unless signature_node

      signed_info_node = signature_node.at_xpath("./*[local-name()='SignedInfo']")
      return failure("no SignedInfo element found") unless signed_info_node

      verify_document_digest(signature_node, signed_info_node, errors)
      verify_signed_properties_digest(signature_node, signed_info_node, errors)
      verify_signature_value(signature_node, signed_info_node, errors)
      verify_signing_certificate_binding(signature_node, errors)

      Result.new(errors.empty?, errors)
    end

    private

    def failure(message)
      Result.new(false, [message])
    end

    # The algorithm actually used to turn a Reference's node-set into octets is whichever C14N
    # transform is last in its Transforms list. Per the XMLDSig spec, when none of a Reference's
    # transforms is itself a canonicalization method (whether because Transforms is absent, as in a
    # real UK ASC-signed document's SignedProperties Reference, or because the only transform is
    # something else entirely, like enveloped-signature, as in a real Spanish Facturae document's
    # document Reference), the *implicit* default is plain Canonical XML 1.0 -- never Exclusive
    # C14N, regardless of what other non-c14n transforms are present.
    def reference_c14n_algorithm(reference_node)
      transforms = reference_node.xpath(".//*[local-name()='Transform']").map { |t| t["Algorithm"] }
      transforms.reverse.find { |uri| Xades::C14N.supported?(uri) } || Algorithms::C14N_1_0
    end

    def reference_digest(reference_node, canonical_bytes, errors, label)
      algorithm_uri = reference_node.at_xpath("./*[local-name()='DigestMethod']")&.[]("Algorithm")
      return Xades::Digest.base64(canonical_bytes, algorithm_uri) if Xades::Digest.supported?(algorithm_uri)

      errors << "unsupported #{label} DigestMethod: #{algorithm_uri.inspect}"
      nil
    end

    # URI="" is the standard way an enveloped signature's Reference names "the whole document" --
    # our own Signer always emits it this way. Matching on that (rather than just "the first
    # Reference with no Type") matters for documents that carry additional untyped references, e.g.
    # a Reference protecting KeyInfo/the certificate (seen in real-world Facturae signatures).
    def verify_document_digest(_signature_node, signed_info_node, errors)
      reference = signed_info_node.at_xpath(".//*[local-name()='Reference'][@URI='']")
      return errors << "missing document Reference in SignedInfo" unless reference

      expected = reference.at_xpath("./*[local-name()='DigestValue']")&.text
      clone = @doc.dup(1)
      clone.at_xpath("//*[local-name()='Signature']").unlink
      canonical = Xades::C14N.canonicalize(clone.root, reference_c14n_algorithm(reference))
      actual = reference_digest(reference, canonical, errors, "document")
      return unless actual

      errors << "document digest mismatch" unless expected == actual
    end

    def verify_signed_properties_digest(signature_node, signed_info_node, errors)
      reference = signed_info_node.at_xpath(
        ".//*[local-name()='Reference'][@Type='#{Algorithms::XADES_SIGNED_PROPERTIES_TYPE}']"
      )
      return errors << "missing SignedProperties Reference in SignedInfo" unless reference

      signed_properties_node = signature_node.at_xpath(".//*[local-name()='SignedProperties']")
      return errors << "missing SignedProperties element" unless signed_properties_node

      expected = reference.at_xpath("./*[local-name()='DigestValue']")&.text
      canonical = Xades::C14N.canonicalize(signed_properties_node, reference_c14n_algorithm(reference))
      actual = reference_digest(reference, canonical, errors, "SignedProperties")
      return unless actual

      errors << "SignedProperties digest mismatch" unless expected == actual
    end

    def verify_signature_value(signature_node, signed_info_node, errors)
      signature_value_node = signature_node.at_xpath("./*[local-name()='SignatureValue']")
      cert_text = signature_node.at_xpath(".//*[local-name()='X509Certificate']")&.text
      return errors << "missing SignatureValue or X509Certificate" unless signature_value_node && cert_text

      signature_method = signed_info_node.at_xpath("./*[local-name()='SignatureMethod']")&.[]("Algorithm")
      algorithm = Algorithms::SIGNATURE_METHODS[signature_method]
      return errors << "unsupported SignatureMethod: #{signature_method.inspect}" unless algorithm

      cert = OpenSSL::X509::Certificate.new(Base64.decode64(cert_text))
      raw_signature = Base64.decode64(signature_value_node.text)
      c14n_algorithm = signed_info_node.at_xpath("./*[local-name()='CanonicalizationMethod']")&.[]("Algorithm")
      bytes = Xades::C14N.canonicalize(signed_info_node, c14n_algorithm || Algorithms::C14N_EXCLUSIVE)

      valid = signature_valid?(cert, algorithm, raw_signature, bytes)
      errors << "signature does not match certificate" unless valid
    end

    def signature_valid?(cert, algorithm, raw_signature, bytes)
      digest = OpenSSL::Digest.new(algorithm[:digest])
      der = to_der_signature(algorithm, raw_signature)
      cert.public_key.verify(digest, der, bytes)
    end

    def to_der_signature(algorithm, raw_signature)
      return raw_signature unless algorithm[:key_type] == :ecdsa

      EcdsaSignature.raw_to_der(raw_signature, raw_signature.bytesize / 2)
    end

    CERT_DIGEST_XPATH = ".//*[local-name()='SigningCertificate' or local-name()='SigningCertificateV2']" \
                         "//*[local-name()='CertDigest']"

    # xades:SigningCertificate(V2)/.../CertDigest is a signed *claim* about which certificate was
    # used. It's covered by the signature (it's inside SignedProperties), so it can't be tampered
    # with in isolation -- but nothing else stops it from simply being wrong/stale from the start
    # (a "certificate substitution" nonconformance some real-world XAdES validators, incl. DSS,
    # reject). We bind the claim to the certificate actually present in KeyInfo.
    def verify_signing_certificate_binding(signature_node, errors)
      cert_digest_node = signature_node.at_xpath(CERT_DIGEST_XPATH)
      return unless cert_digest_node # SigningCertificate is optional at the schema level; nothing to bind

      cert_text = signature_node.at_xpath(".//*[local-name()='X509Certificate']")&.text
      return errors << "SigningCertificate present but no X509Certificate to bind it to" unless cert_text

      verify_cert_digest(cert_digest_node, cert_text, errors)
      verify_issuer_serial_v2_binding(signature_node, cert_text, errors)
    end

    def verify_cert_digest(cert_digest_node, cert_text, errors)
      algorithm_uri = cert_digest_node.at_xpath("./*[local-name()='DigestMethod']")&.[]("Algorithm")
      unless Xades::Digest.supported?(algorithm_uri)
        return errors << "unsupported CertDigest algorithm: #{algorithm_uri.inspect}"
      end

      expected = cert_digest_node.at_xpath("./*[local-name()='DigestValue']")&.text
      actual = Xades::Digest.base64(Base64.decode64(cert_text), algorithm_uri)

      errors << "SigningCertificate digest does not match the embedded certificate" unless expected == actual
    end

    # IssuerSerialV2 is DER (RFC 5035), so a byte comparison against a freshly-recomputed value is
    # exact and implementation-independent (verified against a real DSS fixture during development).
    # We deliberately do NOT attempt the same for the V1 xades:IssuerSerial form: it's a
    # ds:X509IssuerName *string*, and RFC 2253 rendering differs enough across implementations
    # (whitespace, escaping, attribute case) that comparing it byte-for-byte would produce false
    # mismatches on legitimately-valid third-party documents.
    def verify_issuer_serial_v2_binding(signature_node, cert_text, errors)
      issuer_serial_v2_node = signature_node.at_xpath(".//*[local-name()='IssuerSerialV2']")
      return unless issuer_serial_v2_node

      cert = OpenSSL::X509::Certificate.new(Base64.decode64(cert_text))
      expected = issuer_serial_v2_node.text.strip
      actual = Xades::Certificate.issuer_serial_v2_base64_for(cert)

      errors << "IssuerSerialV2 does not match the embedded certificate's issuer/serial" unless expected == actual
    end
  end
end
