require 'merb-core'
require 'merb-auth-core'

path = File.expand_path(File.dirname(__FILE__)) / "merb-authz"
require path / "authorization"
require path / "authorizable_mixin"
require path / "policy"




Merb::BootLoader.before_app_loads do
  # require code that must be loaded before the application
end

Merb::BootLoader.after_app_loads do
  # code that can be required after the application loads
end

Merb::Plugins.add_rakefiles "merb-authz/merbtasks"


Object.class_eval do
  extend Merb::Authorization::Trigger
end
