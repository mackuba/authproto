# frozen_string_literal: true

describe AuthProto::State::TokenSet do
  let(:access_token) { "valid_access_token" }
  let(:refresh_token) { "valid_refresh_token" }
  let(:token_type) { "DPoP" }
  let(:expires_in) { 3600 }
  let(:scope) { "read write" }
  let(:sub) { "did:example:1234" }
  let(:token_set) do
    AuthProto::State::TokenSet.new(
      access_token: access_token,
      token_type: token_type,
      expires_in: expires_in,
      refresh_token: refresh_token,
      scope: scope,
      sub: sub
    )
  end

  describe "#initialize" do
    it "should initialize with valid parameters" do
      token_set.access_token.should == access_token
      token_set.refresh_token.should == refresh_token
      token_set.token_type.should == token_type
      token_set.scope.should == scope
      token_set.sub.should == sub
      token_set.expires_at.should be_an_instance_of(Time)
      token_set.expires_at.should be > Time.now
    end

    ['DPoP', 'dpop', 'DPOP', 'dPoP'].each do |type|
      context "with token_type #{type}" do
        let(:token_type) { type }

        it "should accept the token type and return its canonical spelling" do
          token_set.token_type.should == 'DPoP'
        end
      end
    end

    [nil, 123, false, 'Bearer', 'DPoP '].each do |type|
      context "with invalid token_type #{type.inspect}" do
        let(:token_type) { type }

        it "should reject the token type with ArgumentError" do
          expect { token_set }.to raise_error(ArgumentError, /token_type must be DPoP/)
        end
      end
    end

    it "should raise an error if token_type is not 'DPoP'" do
      expect {
        AuthProto::State::TokenSet.new(
          access_token: access_token,
          token_type: "Bearer",
          expires_in: expires_in,
          refresh_token: refresh_token,
          scope: scope,
          sub: sub
        )
      }.to raise_error(ArgumentError)
    end

    it "should raise an error if required parameters are missing" do
      expect {
        AuthProto::State::TokenSet.new(
          access_token: nil,
          token_type: token_type,
          expires_in: expires_in,
          refresh_token: refresh_token,
          scope: scope,
          sub: sub
        )
      }.to raise_error(ArgumentError)

      expect {
        AuthProto::State::TokenSet.new(
          access_token: access_token,
          token_type: token_type,
          expires_in: expires_in,
          refresh_token: refresh_token,
          scope: nil,
          sub: sub
        )
      }.to raise_error(ArgumentError)

      expect {
        AuthProto::State::TokenSet.new(
          access_token: access_token,
          token_type: token_type,
          expires_in: expires_in,
          refresh_token: refresh_token,
          scope: scope,
          sub: nil
        )
      }.to raise_error(ArgumentError)
    end

    it "should raise an error if expires_in is not an integer" do
      expect {
        AuthProto::State::TokenSet.new(
          access_token: access_token,
          token_type: token_type,
          expires_in: "1",
          refresh_token: refresh_token,
          scope: scope,
          sub: sub
        )
      }.to raise_error(ArgumentError)
    end
  end

  describe "#renewable?" do
    it "should return true if refresh_token is present" do
      token_set.renewable?.should be true
    end

    it "should return false if refresh_token is nil" do
      token_set_without_refresh = AuthProto::State::TokenSet.new(
        access_token: access_token,
        token_type: token_type,
        expires_in: expires_in,
        scope: scope,
        sub: sub
      )
      token_set_without_refresh.renewable?.should be false
    end
  end

  describe "#expired?" do
    it "should return false if token has not expired" do
      token_set.expired?.should be false
    end

    it "should return true if token has expired" do
      expired_token_set = AuthProto::State::TokenSet.new(
        access_token: access_token,
        token_type: token_type,
        expires_in: 1,
        refresh_token: refresh_token,
        scope: scope,
        sub: sub
      )
      # Force the token to appear expired
      expired_token_set.instance_variable_set(:@expires_at, Time.now - 10)
      expired_token_set.expired?.should be true
    end

    it "should respect the buffer parameter for expiration check" do
      token_set_with_buffer = AuthProto::State::TokenSet.new(
        access_token: access_token,
        token_type: token_type,
        expires_in: 10,
        refresh_token: refresh_token,
        scope: scope,
        sub: sub
      )
      token_set_with_buffer.expired?(15).should be true
    end
  end
end
