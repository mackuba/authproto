# frozen_string_literal: true

require_relative 'errors'

module AuthProto

  #
  # Manages OAuth state for AT Protocol authorization flows. This module provides thread-safe
  # storage and management of authorization session data, including tokens, PKCE values,
  # and identity information.
  #
  # The module consists of three main components:
  #
  # 1. {TokenSet} - Represents OAuth tokens (access and refresh) with their metadata,
  #    including expiration times, scope, and the authenticated user's DID.
  #
  # 2. {Session} - Tracks the complete state of an authorization flow, including:
  #    - PKCE verifier/challenge pairs
  #    - State tokens for request verification
  #    - Authorization server information
  #    - Current tokens and user identity (DID)
  #
  # 3. {SessionManager} - Provides thread-safe storage and retrieval of active sessions,
  #    with support for lookup by session ID or state token.
  #
  # @example Creating and managing a session
  #   manager = AuthProto::State::SessionManager.new
  #
  #   # Create a new session
  #   session = manager.create_session(
  #     client_id: "https://myapp.com/oauth-client-metadata.json",
  #     scope: "atproto"
  #   )
  #
  #   # Update session with tokens
  #   tokens = AuthProto::State::TokenSet.new(
  #     access_token: "...",
  #     token_type: "DPoP",
  #     expires_in: 3600,
  #     scope: "atproto",
  #     sub: "did:plc:abcdef123"
  #   )
  #   session.tokens = tokens
  #   manager.update_session(session)
  #
  #   # Lookup session later
  #   session = manager.get_session(session.session_id)
  #   if session.authorized?
  #     puts "Access token: #{session.tokens.access_token}"
  #   end
  #
  # Session mutation is synchronized, and the session manager uses backend locks
  # when persisting changes. TokenSet values themselves are read-only.
  #

  module State

    # Error raised for session-related issues
    class SessionError < AuthProto::Error; end
  end
end
