# frozen_string_literal: true

require 'didkit/did'
require 'uri'

require_relative '../errors'
require_relative '../validated_uri'

module AuthProto
  module Token

    # Error raised when a token subject cannot be bound to the session's PDS.
    class IdentityError < AuthProto::Error; end

    # Error raised when the subject or its resolved PDS differs from the session binding.
    class IdentityMismatchError < IdentityError; end

    # Error raised when a DID document cannot be fetched.
    class IdentityLookupError < IdentityError; end


    #
    # Shared verification of a token subject's current PDS.
    #

    module Identity

      private

      def validate_subject_pds(subject, session)
        raise IdentityError, "Session is missing its PDS; authorize again" unless session.pds

        begin
          pds = DIDKit::DID.new(subject).document.pds_endpoint
        rescue DIDKit::DIDError, DIDKit::FormatError => e
          raise IdentityError, "Invalid token subject: #{e.message}"
        rescue StandardError => e
          raise IdentityLookupError, "Could not resolve token subject: #{e.message}"
        end

        raise IdentityError, "Subject DID document has no PDS endpoint" unless pds

        pds_uri = ValidatedURI.new(pds)
        session_uri = ValidatedURI.new(session.pds)

        unless pds_uri.origin.casecmp?(session_uri.origin)
          raise IdentityMismatchError, "Subject PDS does not match session PDS"
        end
      rescue URI::InvalidURIError => e
        raise IdentityError, "Invalid token subject: #{e.message}"
      end
    end
  end
end
