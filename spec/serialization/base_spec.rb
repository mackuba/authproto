# frozen_string_literal: true

require 'json'

class TestSerializer < AuthProto::Serialization::Base
  def type_identifier
    "Test"
  end

  private

  def serialize_data(obj)
    { "value" => obj }
  end

  def deserialize_data(data)
    data["value"]
  end

  def validate_object(obj)
    raise AuthProto::Serialization::ValidationError unless obj.is_a?(String)
  end
end

describe AuthProto::Serialization::Base do
  let(:serializer) { TestSerializer.new }
  let(:sample_data) { "test data" }

  describe "#serialize" do
    it "should create valid serialized format" do
      result = JSON.parse(serializer.serialize(sample_data))

      result["version"].should == AuthProto::Serialization::Base::CURRENT_VERSION
      result["type"].should == "Test"
      (result["created_at"]).should be_truthy
      (result["updated_at"]).should be_truthy
      (result["data"]).should be_truthy
    end

    it "should encrypt sensitive fields" do
      sensitive_data = { "access_token" => "secret" }
      serializer.stubs(:serialize_data).returns(sensitive_data)

      result = JSON.parse(serializer.serialize("test"))
      encrypted = result["data"]["access_token"]

      (encrypted.key?("version")).should be_truthy
      (encrypted.key?("iv")).should be_truthy
      (encrypted.key?("data")).should be_truthy
      (encrypted.key?("tag")).should be_truthy
    end

    it "should raise ValidationError for invalid objects" do
      expect {
        serializer.serialize(123)
      }.to raise_error(AuthProto::Serialization::ValidationError)
    end
  end

  describe "#deserialize" do
    it "should correctly deserialize and decrypt data" do
      serialized = serializer.serialize(sample_data) # { "value" => obj }
      deserialized = serializer.deserialize(serialized) # data["value"]

      deserialized.should == sample_data
    end

    it "should raise Error for invalid JSON" do
      expect {
        serializer.deserialize("invalid json")
      }.to raise_error(AuthProto::Serialization::Error)
    end

    it "should raise TypeMismatchError for wrong type" do
      serialized = TestSerializer.new.serialize(sample_data)
      data = JSON.parse(serialized)
      data["type"] = "Wrong"

      expect {
        serializer.deserialize(JSON.generate(data))
      }.to raise_error(AuthProto::Serialization::TypeMismatchError)
    end

    it "should raise VersionError for unsupported version" do
      serialized = TestSerializer.new.serialize(sample_data)
      data = JSON.parse(serialized)
      data["version"] = 999

      expect {
        serializer.deserialize(JSON.generate(data))
      }.to raise_error(AuthProto::Serialization::VersionError)
    end
  end
end
