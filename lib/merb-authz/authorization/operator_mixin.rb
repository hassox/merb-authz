# This is the main mixin to use authorization in MerbAuth.  
# Mix this into an "operator" class to allow authorisation with respect to it.
# An "operator" class is a User, or an Account, or something that is
# asking for permission.
module Merb
  class Authorization
    module Policies; end # Container for policies to be put into for class string lookup
    
    module OperatorMixin
      
      # The work horse of authorization.  All authorization requests come through here baby.
      def authorized?(label, opts = {})
        operator  = self
        !!auth_cache.run_policies(operator, label, opts)
      end
      
      # Use this to access the cache for the operator
      # The entire cache is here
      # :api: public
      def auth_cache(&block)
        return @authorization if @authorization
        @authorization ||= OperatorCache.new(self.class)
        @authorization.instance_eval(&block) if block_given?
        @authorization
      end
      
    end
    
    class OperatorCache
      attr_reader :options, :policy_cache
      
      def initialize(opts = {})
        @options  = opts
        @policy_cache = Hash.new{|h,k| h[k] = {}}
        self
      end
      
      # Check to see if this authorization request is cached
      # :api: private
      def use_cache?(opts = {})
        return true if opts[:cache].nil?
        opts[:cache]
      end
      
      # Run the policies for this operator
      # :api: private
      def run_policies(operator, label, opts)
        key = opts.dup  # ignore the cache option in the key
        key.delete(:cache)
        key = key.to_a

        args = opts[:target].nil? ? [label] : [label, opts[:target]] # work out which policies to grab
        policies = Merb::Authorization.policies_from_label(*args)
        
        # If we're allowed to cache, and the item has already been run, return that
        if use_cache?(opts)
          already_run = check_cache(policies, key)
          return true if already_run == true
          policies = policies - already_run
        end
        
        # Runnem
        result = false
        policies.each do |policy|
          result = run_policy(operator, policy, use_cache?(opts), key, opts)
          break if result
        end
        result
      end
      
      # check the cache for a hit
      # :api: private
      def check_cache(policies, key)
        already_run = []
        policies.each do |p|
          cached_result = policy_cache[p][key]
          if cached_result # return if it passed
            return true 
          else 
            # Reject the policy from the policies if it's false, i.e. previously failed
            already_run << p unless cached_result.nil?
          end        
        end
        already_run
      end
      
      # Run the actual policy 
      # :api: private
      def run_policy(op, policy, cache, key, opts)
        target    = opts[:target]
        type = (target.nil? || target.kind_of?(Class)) ? :general : :instance
        result = case target
        when Class, nil
          policy.new.general_policy(op, opts)
        else
          policy.new.instance_policy(op,target,opts)
        end
        cache_result(policy, !!result, key) if cache
        result
      end
      
      # Caches the result
      # :api: private
      def cache_result(policy, result, key)
        policy_cache[policy][key] = result
      end
      
    end # OperatorCache
  
  end # Authorization
end #Merb