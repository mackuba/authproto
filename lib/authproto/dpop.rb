# frozen_string_literal: true

module AuthProto

  #
  # Demonstrating Proof of Possession (DPoP) signing and request authentication.
  #

  module DPoP

    # JWS signing algorithm used for DPoP proofs.
    # @return [String]
    ALGORITHM = "ES256"

    # OAuth error value requesting a retry with a server-provided DPoP nonce.
    # @return [String]
    ERROR_USE_NONCE = "use_dpop_nonce"
  end
end
