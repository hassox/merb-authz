module Merb
  class Authorization
    
    module Trigger
      # This is a trigger module to allow setting up authorization on an object
      def authorizable!
        self.class_eval do
          include Merb::Authorization::Authorizable
        end
      end # authorizable!
    end # Setup
    
    module Authorizable
      def self.included(base)
        base.class_eval do
          extend Merb::Authorization::Authorizable::ClassMethods
          include Merb::Authorization::Authorizable::InstanceMethods
        end
      end
      
      module ClassMethods
        class Configuration
          attr_accessor :labels, :strategies
        end
        
        # Hash based setup
        # def authorize_with(setup)
        #   setup.each do |k, v|
        #     keys = [k].flatten
        #     keys.each do |label|
        #       labeled_policies[label] = v
        #     end
        #   end 
        # end
        
        def authorize
          raise "You must supply a block to authorize" unless block_given?
          yield
        end
        
        def with(*labels)
          raise "Prior 'with' not completed with 'use'" if @_m_a_current_config
          @_m_a_current_config = Configuration.new
          @_m_a_current_config.labels = labels.flatten 
          self
        end
        
        def use(*strategies, &block)
          strategies << block if block
          @_m_a_current_config.strategies = strategies.flatten
          @_m_a_current_config.labels.each do |l|
            labeled_policies[l] = strategies
          end
          @_m_a_current_config = nil
          self
        end 
        
        def lookup_policy_or_label(label_or_policy)
          policy = lookup_policy[label_or_policy]     
          policy ||= labeled_policies[label_or_policy]
          raise PolicyNotFound, "#{label_or_policy}" if policy.blank?
          policy
        end
        
        private
        def labeled_policies
          @_m_a_policy_labels ||= {}
        end
        
        # Keeps track of strategies by class or string
        # When loading from string, strategies are loaded withing the Merb::Authentication::Strategies namespace
        # When loaded by class, the class is stored directly
        # @private
        def lookup_policy
          @policy_lookup || reset_policy_lookup!
        end

        # Restets the strategy lookup.  Useful in specs
        def reset_policy_lookup!
          @policy_lookup = Mash.new do |h,k| 
            case k
            when Class, Proc
              h[k] = k
            when String, Symbol
              begin
                h[k] = Merb::Authorization::Policies.full_const_get(k.to_s) 
              rescue 
                nil # If it's not found just be silent
              end
            end
          end
        end
      end # ClassMethods
      
      module InstanceMethods
        
        def authorized?(user, *policies)
          result = nil
          result = _m_a_excecute_policies(user, *policies)
          raise Merb::Controller::Unauthorized unless result
          !!result        
        end
        
        private
        def _m_a_excecute_policies(user, *policies)
          result = nil
          policies.each do |p|
            policy_or_group = self.class.lookup_policy_or_label(p)
            case policy_or_group
            when Array
              result = _m_a_excecute_policies(user, *policy_or_group)
            when Proc
              if _m_a_attempt_policy?(policy_or_group.inspect)
                result = policy_or_group.call(self,user)              
              end
            else
              if _m_a_attempt_policy?(the_policy = self.class.lookup_policy_or_label(policy_or_group))
                result = the_policy.new.run!(self, user)
              end
            end
            break if result
          end
          result
        end
        
        def _m_a_attempt_policy?(policy)
          return false if _m_a_attempted_policies.include?(policy)
          _m_a_attempted_policies << policy
          true
        end
        
        def _m_a_attempted_policies
          @_m_a_attempted_policies ||= []
        end
        
      end # InstanceMethods
        
    end # Authorizable
  end # Authorization
end # Merb