# frozen_string_literal: true

describe AuthProto do
  it "should have a VERSION constant defined" do
    AuthProto.const_defined?(:VERSION).should be true
  end
end
