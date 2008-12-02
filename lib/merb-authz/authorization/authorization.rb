module Merb
  class Authorization
    
    # Grabs the policies for this item
    # :api: plugin
    def self.policies_from_label(label, target = nil)
      target = case target
      when nil
        self
      when Class
        target
      else
        target.class
      end
      
      result = nil
      # Check the label for first the target if there is one, and next the global policies
      [target, self].each do |obj|
        next unless obj.authorization.label?(label)
        result = obj.authorization[label].policy_classes unless obj.authorization[label].policy_classes.blank?
      end
      return result unless result.blank?
      raise Merb::Authorization::PolicyNotFound
    end
    
    # Grabs policies from a string
    # :api: plugin
    def self._policy_from_string(policy)
      @policy_from_string ||= Mash.new do |h,k|
        h[k] = begin
          Merb::Authorization::Policies.const_get(k.to_s)
        rescue NameError => e
          raise PolicyNotFound, e.message
        end
      end
      @policy_from_string[policy]
    end # policy_from_string
    
    # Grabs the policies / policy strings associated with a scope
    def self._policies_from_scope(label, scope)
      policies = []
      klass = scope.reverse.detect do |klass|
        klass.authorization.label?(label) && !klass.authorization[label].policy_classes.blank?
      end
      raise Merb::Authorization::PolicyNotFound if klass.nil?
      klass.authorization[label].policy_classes
    end
    
    # Accesses global policies
    # :api: plugin
    def self.[](label)
      self.authorization[label]
    end
    
    # Use this method to add global policies
    # :api: public
    def self.global_policies(&block)
      self.authorization(&block)
    end
    
  end # Authorization
end # Merb