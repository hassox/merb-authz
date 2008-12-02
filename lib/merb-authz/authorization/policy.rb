# The base policy class.  Inherit from this as the base for your policies
# Each policy may implement one or both of the general_policy and instance_policy class methods
# 
# If a method isn't defined, it will return false so that it is essentially skipped 
# and moves onto the next policy
module Merb::Authorization::Policies
  class Policy
    
    def self.general_policy(operator, opts = {})
      return false
    end
    
    def self.instance_policy(operator, opts ={})
      return false
    end
    
  end # Policy
end # Merb::Autorization