# frozen_string_literal: true

module AuthProto

  #
  # Demonstrating Proof of Possession (DPoP) signing and request authentication.
  #

  module DPoP

    # JWS signing algorithm used for DPoP proofs.
    # @return [String]
    ALGORITHM = "ES256"

    ERROR_USE_NONCE = "use_dpop_nonce"
  end
end
