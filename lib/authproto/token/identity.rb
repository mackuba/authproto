# frozen_string_literal: true

require 'didkit/did'
require 'uri'

require_relative '../errors'

module AuthProto
  module Token

    # Error raised when a token subject cannot be bound to the session's PDS.
    class IdentityError < AuthProto::Error; end


    #
    # Shared verification of a token subject's current PDS.
    #

    module Identity

      private

      def validate_subject_pds(subject, session)
        raise IdentityError, "Session is missing its PDS; authorize again" unless session.pds

        pds = DIDKit::DID.new(subject).document.pds_endpoint

        unless pds && URI(pds).origin.downcase == URI(session.pds).origin.downcase
          raise IdentityError, "Subject PDS does not match session PDS"
        end
      rescue DIDKit::DIDError, DIDKit::FormatError => e
        raise IdentityError, "Invalid token subject: #{e.message}"
      end
    end
  end
end
