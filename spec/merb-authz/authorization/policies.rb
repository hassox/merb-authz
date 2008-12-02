module  Merb::Authorization::Policies
  
    class AbstractTestPolicy < Policy
      def general_policy(op,inst,opts = {})
        Viking.capture([self.class, :general])
        return false
      end
    
      def instance_policy(op,inst,opts = {})
        Viking.capture([self.class, :instance])
        return false
      end
    end # AbstractTestPolicy
  
    class StringAsPass < AbstractTestPolicy
    
      def general_policy(operator, options = {})
        super
        operator.respond_to?(:name) && operator.name =~ /pass/
      end
    
      def instance_policy(operator, instance, options = {})
        super
       (instance.kind_of?(String) && instance =~ /pass/i ) || (operator.respond_to?(:name) && operator.name =~ /pass/)
      end
    end
  
    class HashWithPass < AbstractTestPolicy
      def instance_policy(operator, instance, options = {})
        super
        instance.kind_of?(Hash) && instance[:pass] || (operator.respond_to?(:name) && operator.name =~ /pass/)
      end
    end
  
    class UseOptions < AbstractTestPolicy
      def general_policy(operator, opts = {})
        super
        return opts["pass"] || (operator.respond_to?(:name) && operator.name =~ /pass/)
      end
    
      def instance_policy(operator, instance, opts = {})
        super
        return opts["pass"] || (operator.respond_to?(:name) && operator.name =~ /pass/)
      end
    end
  
    class AlwaysAllow < AbstractTestPolicy
      def general_policy(operator, opts = {})
        super
        return true
      end
    
      def instance_policy(op, inst, opts = {})
        super
        return true
      end
    end
    
    class Create  <  AbstractTestPolicy; end
    class Read    <  AbstractTestPolicy; end
    class Update  <  AbstractTestPolicy; end
    class Delete  <  AbstractTestPolicy; end
    class Custom  <  AbstractTestPolicy; end
end