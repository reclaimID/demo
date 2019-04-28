require 'yaml'

class DemoConfig
  def self.load
    return YAML.load File.read "config.yml"
  end
end
