# frozen_string_literal: true

module Xades
  module Builder
    # Builds the <xades:QualifyingProperties>/<xades:SignedProperties> fragment: SigningTime +
    # SigningCertificate (V1, ds:X509IssuerName/X509SerialNumber) or V2 (xades:IssuerSerialV2, RFC 5035).
    module QualifyingProperties
      def self.build(certificate:, signature_id:, signed_properties_id:, signing_time:, version: :v2)
        <<~XML.strip
          <xades:QualifyingProperties xmlns:xades="#{Algorithms::XADES_NAMESPACE}" xmlns:ds="#{Algorithms::DS_NAMESPACE}" Target="##{signature_id}"><xades:SignedProperties Id="#{signed_properties_id}"><xades:SignedSignatureProperties><xades:SigningTime>#{format_time(signing_time)}</xades:SigningTime>#{signing_certificate(certificate, version)}</xades:SignedSignatureProperties></xades:SignedProperties></xades:QualifyingProperties>
        XML
      end

      def self.format_time(time)
        time.utc.strftime("%Y-%m-%dT%H:%M:%SZ")
      end
      private_class_method :format_time

      def self.signing_certificate(certificate, version)
        case version
        when :v2 then signing_certificate_v2(certificate)
        when :v1 then signing_certificate_v1(certificate)
        else raise ArgumentError, "signing_certificate_version must be :v1 or :v2, got #{version.inspect}"
        end
      end
      private_class_method :signing_certificate

      def self.cert_digest(certificate)
        <<~XML.strip
          <ds:DigestMethod Algorithm="#{Algorithms::DIGEST_SHA256}"/><ds:DigestValue>#{certificate.sha256_digest_base64}</ds:DigestValue>
        XML
      end
      private_class_method :cert_digest

      def self.signing_certificate_v2(certificate)
        <<~XML.strip
          <xades:SigningCertificateV2><xades:Cert><xades:CertDigest>#{cert_digest(certificate)}</xades:CertDigest><xades:IssuerSerialV2>#{certificate.issuer_serial_v2_base64}</xades:IssuerSerialV2></xades:Cert></xades:SigningCertificateV2>
        XML
      end
      private_class_method :signing_certificate_v2

      def self.signing_certificate_v1(certificate)
        <<~XML.strip
          <xades:SigningCertificate><xades:Cert><xades:CertDigest>#{cert_digest(certificate)}</xades:CertDigest><xades:IssuerSerial><ds:X509IssuerName>#{Util.escape_xml_text(certificate.issuer_name)}</ds:X509IssuerName><ds:X509SerialNumber>#{certificate.serial}</ds:X509SerialNumber></xades:IssuerSerial></xades:Cert></xades:SigningCertificate>
        XML
      end
      private_class_method :signing_certificate_v1
    end
  end
end
