require 'yard'

YARD::Parser::SourceParser.after_parse_list do
  fields = YARD::Registry.at('AuthProto::PAR::Request::Fields').attributes[:instance]

  {
    'AuthProto::PAR::Request' => false,
    'AuthProto::PAR::Request::Configuration' => true
  }.each do |path, writable|
    target = YARD::Registry.at(path)

    fields.each do |name, attribute|
      original = attribute[:read]

      reader = YARD::CodeObjects::MethodObject.new(target, name, :instance)
      reader.docstring = original.docstring.to_raw
      reader.signature = "def #{name}"

      target.attributes[:instance][name] = { read: reader, write: nil }

      next unless writable

      return_tag = reader.tag(:return)
      return_tag.types = (return_tag.types + ['nil']).uniq

      writer = YARD::CodeObjects::MethodObject.new(target, "#{name}=", :instance)
      writer.docstring = original.docstring.to_raw
      writer.parameters = [['value', nil]]
      writer.signature = "def #{name}=(value)"

      target.attributes[:instance][name][:write] = writer
    end
  end
end
