$TESTING=true
$:.push File.join(File.dirname(__FILE__), '..', 'lib')

require 'rubygems'
require 'merb-core'
require 'merb-core/test'
require 'merb-core/dispatch/session'
require 'spec' # Satisfies Autotest and anyone else not using the Rake tasks
require 'merb-authz'


Merb.start  :environment    => "test", 
            :adapter        => "runner", 
            :session_store  => "cookie", 
            :session_secret_key => "d3a6e6f99a25004da82b71af8b9ed0ab71d3ea21"



Spec::Runner.configure do |config|
  config.include(Merb::Test::ViewHelper)
  config.include(Merb::Test::RouteHelper)
  config.include(Merb::Test::ControllerHelper)
end

class Capturer
  cattr_accessor :captures
  @@captures = []
end

class User
  attr_accessor :pass_for, :name
end

MAP = Merb::Authorization::Policies