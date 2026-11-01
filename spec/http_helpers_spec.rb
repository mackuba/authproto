# frozen_string_literal: true

describe AuthProto::HTTPHelpers do
  let(:helper) { Class.new { include AuthProto::HTTPHelpers }.new }

  ['content-type', 'Content-Type', 'cOnTeNt-TyPe'].each do |header_name|
    it "should find #{header_name} using any case in the requested name" do
      response = { headers: { 'Other-Header' => 'other', header_name => 'Application/JSON; charset=utf-8' } }

      ['content-type', 'Content-Type', 'CONTENT-TYPE'].each do |name|
        helper.send(:response_header, response, name).should == 'Application/JSON; charset=utf-8'
      end
    end
  end

  [{}, { headers: nil }, { headers: {} }, { headers: { 'Other-Header' => 'other' } }].each do |response|
    it "should return nil when the header is absent from #{response.inspect}" do
      helper.send(:response_header, response, 'Content-Type').should be_nil
    end
  end

  it "should preserve an empty header value" do
    helper.send(:response_header, { headers: { 'DPoP-Nonce' => '' } }, 'dpop-nonce').should == ''
  end

  {
    ' Application/JSON ; charset=utf-8; other=value' => 'Application/JSON',
    ' application/json ' => 'application/json',
    '' => '',
    '; charset=utf-8' => ''
  }.each do |value, expected|
    it "should strip parameters and surrounding whitespace from #{value.inspect} when requested" do
      response = { headers: { 'Content-Type' => value } }

      helper.send(:response_header, response, 'content-type', strip_parameters: true).should == expected
      helper.send(:response_header, response, 'content-type', strip_parameters: false).should == value
    end
  end

  it "should return nil for a missing header when stripping parameters" do
    helper.send(:response_header, {}, 'Content-Type', strip_parameters: true).should be_nil
  end

  it "should keep the helper private when included" do
    helper.class.private_method_defined?(:response_header).should be true
    helper.class.public_method_defined?(:response_header).should be false
  end
end
