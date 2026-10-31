# frozen_string_literal: true

describe AuthProto::PKCE do
  let(:pkce) { described_class.new }

  it "should generate a 43-character verifier using only permitted characters" do
    pkce.verifier.length.should == 43
    pkce.verifier.should match(/\A[A-Za-z0-9._~-]+\z/)
  end

  it "should generate a 43-character URL-safe challenge without padding" do
    pkce.challenge.length.should == 43
    pkce.challenge.should match(/\A[A-Za-z0-9_-]+\z/)
  end

  it "should generate the S256 challenge matching the RFC 7636 example verifier" do
    verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
    SecureRandom.stubs(:urlsafe_base64).with(32, false).returns(verifier)

    pkce.verifier.should == verifier
    pkce.challenge.should == 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'
  end

  it "should generate a fresh pair for each instance" do
    other = described_class.new

    pkce.verifier.should_not == other.verifier
    pkce.challenge.should_not == other.challenge
  end

  it "should prevent mutation of the verifier and challenge" do
    pkce.verifier.should be_frozen
    pkce.challenge.should be_frozen
  end

  it "should raise a PKCE error if random generation fails" do
    SecureRandom.stubs(:urlsafe_base64).raises(RuntimeError, "Random generation failed")

    expect { described_class.new }.to raise_error(AuthProto::PKCE::Error, /Random generation failed/)
  end
end
