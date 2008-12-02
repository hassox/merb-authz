module Merb
  class Authorization
    class OpenForLabelStatement < Exception; end
    class NoCurrentForLabelStatement < Exception; end
    class PolicyNotFound < Merb::Controller::NotFound; end
    
    class ClassHelper
      attr_accessor :working_labels, :scope_context, :klass
      
      def initialize
        self.reset_policy_groups!
        @scope_context = [Merb::Authorization] # Global context
        @working_labels = []
      end
      
      # Provides a list of labels for this class
      # :api: public
      def labels(label = nil)
        @labels ||= Hash.new{|h,k| h[k] = PolicyHelper.new }
        label.nil? ? @labels : @labels[label]
      end
      alias_method :[], :labels
      
      # Checks to see if this label is setup
      # :api: plugin
      def label?(label)
        self.labels.keys.include?(label)
      end
      
      
      # Use this to reset your policy groups for the class.  It's useful 
      # for specs especially
      # :api: plugin
      def reset_policy_groups!
        @labels = nil
      end
          
      # Use this to clear policies that may be set for a label
      def clear!
        raise NoCurrentForLabelStatement if working_labels.empty?
        working_labels.each{|l| labels.delete(l)}
      end
      
      # Sets up the labels that you want to use for the following group of policies.
      # Any number of labels may be given here as aliases for the same group.
      # :api: public
      def for_labels(*the_labels)
        raise OpenForLabelStatement unless working_labels.empty?
        self.working_labels += the_labels
        self
      end
      alias_method :for_label, :for_labels
      
      # This tells the label which policies to associate with it. 
      # You must namespace your policies under Merb::Authorization::Policies and list 
      # the policies as class strings
      #
      # Example
      #   with(:label).use("AdminPolicy")
      #
      # You may also use previoulsy defined policy group labels to add an entire group
      #  
      # Example
      #   with(:label1).use("AdminPolicy", "PublisherPolicy")
      #   with(:label2).use(:label1, "PublicPolicy")
      #
      # Note: 
      # use_policies will overwrite any inherited policies.  To add to inherited policies use add_policies
      # 
      # You can also use global policy groups.  Class level labels will take precedence over global ones
      # :api: public
      def use_policies(*policies_or_labels)
        add_policies_to_labels(policies_or_labels, true)
      end
      alias_method :use_policy, :use_policies
      
      # add_policies is the same as use_policies except that it will add
      # to any inherited policies if there are any.  You can use this method always
      # if you choose and it will automatically pick up any inherited policies if present
      # 
      # :api: public
      def add_policies(*policies_or_labels)
        add_policies_to_labels(policies_or_labels, false)
      end
      alias_method :add_policy, :add_policies
      
      # Use the with_scope method to copy policy groups from other
      # classes already defined.  
      # :api: public
      def use_scopes(*klasses, &block)
        self.scope_context += klasses.flatten
        yield
        self.scope_context -= klasses.flatten
        nil # should not be chained
      end
      alias_method :use_scope, :use_scopes
      alias_method :copy_scope, :use_scopes
      
      # Used to deep dup the policies for this class during inheriting
      # :api: private
      def dup
        tmp = self.class.new
        tmp.instance_variable_set("@labels", deep_copy_label_hash(@labels))
        tmp
      end
      
      private
      def add_policies_to_labels(policies_or_labels, clear_first = false)
        raise NoCurrentForLabelStatement if working_labels.empty?
        
        working_labels.each do |l| # Add each of the policies to the given labels
          if clear_first
            labels[l] = PolicyHelper.new
          else
            labels[l] ||= PolicyHelper.new
          end
          labels[l].policies += [*policies_or_labels]
          labels[l].scope = scope_context.dup
          raise "UnknownError" unless klass
          labels[l].scope << klass
        end
        # reset the object ready for the next decleration
        working_labels.clear
        self
      end

      # Used to dup for inheritance
      def deep_copy_label_hash(hash)
        tmp = Hash.new{|h,k| h[k] = PolicyHelper.new }
        hash.each do |k,v|
          tmp[k] = v.dup
        end
        tmp
      end
          
      # Manages the policy list
      class PolicyHelper
        
        # Sets the current scope or policies of the labels.
        # Add symbol (labels) or strings (policy class strings) to te policies array
        # :api: plugin
        attr_accessor :scope, :policies
        
        def initialize(*args)
          @policies = [*args]
          @scope = [Merb::Authorization]
          self
        end
        
        # Provides access to the actual policy classes assigned to this 
        # label
        # :api: plugin
        def policy_classes
          fetch_policies! unless @fetched
          @policy_classes
        end
        
        # Extracts the policy classes from the labels
        # :api: plugin
        def fetch_policies!
          @fetched = true
          @policy_classes = @policies.map do |pol|
            result = case pol
            when String
              Merb::Authorization._policy_from_string(pol)
            when Symbol
              Merb::Authorization._policies_from_scope(pol, scope)
            end
          end
          @policy_classes = @policy_classes.flatten.compact
        end
          
        # Overwrite here for inheriting
        def dup
          PolicyHelper.new(*policies)
        end
      end # PolicyHelper
    end # ClassHelper

  end # Authorization
end # Merb