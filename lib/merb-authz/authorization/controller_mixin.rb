class Merb::AbstractController
  class Unauthorized < Merb::Controller::Forbidden; end
  class_inheritable_accessor :_authorization

  # DOX NEEDED HERE
  def self.authorization(klass = nil, &block)
    @_authorization_klass = klass
    self._authorization ||= Merb::Authorization::ControllerHelper.new
    self._authorization.instance_eval(&block) if block_given?
    before :_check_authorization
    self._authorization
  end
  
  # This is the workhorse of checking in a controller.  You should not ever need to actually 
  # call this directly, instead just make sure that there is a before for this method
  private 
  def _check_authorization
    # Log the user in if they're not logged in
    ensure_authenticated unless session.authenticated?
    if self.class.authorization[params[:action]].active?
      config = self.class.authorization[params[:action]]
      opts = {}
      [:target, :options].each do |item|
        val = case config.send(item)
        when nil
          nil
        when Proc
          self.instance_eval(config.send(item))
        when Symbol
          self.send(config.send(item))
        when Class
          config.send(item)
        end
        if item == :options
          opts.merge!(val) if val
        else
          opts.merge!(item => val) if val
        end
      end
      opts[:target] ||= @_authorization_klass if @_authorization_klass
      raise Unauthorized if !current_user.authorized?(config.label, opts)
    end
    
    # Overwite current_user to change the user that will be authorized by default
    # :api: overwritable
    def current_user
      session.user
    end
  end # _check_authorization
end # Merb::AbstractController

# Adjust the Merb::Controller so that it is overwritable
class Merb::Controller; override! :current_user; end

# A Helper to manage controller setup for authorization
class Merb::Authorization
  class ControllerHelper
    class NoForActionStatement < Merb::Controller::InternalServerError; end
    
    attr_accessor :_actions, :target_context, :option_context, :working_actions
    
    def initialize
      @target_context = []
      @option_context = []
      @working_actions = []
    end
    
    # Provides access to the actual configuration objects via hash lookup
    # :api: plugins
    def _actions(action = nil)
      @_actions ||= Mash.new{|h,k| h[k] = ActionManager.new}
      action.nil? ? @_actions : @_actions[action]
    end
    alias_method :[], :_actions
    
    # Declare which actions are applicable to use for this decleration
    # :api: public
    def for_actions(*actions)
      self.working_actions = actions
      self
    end
    alias_method :actions,      :for_actions
    alias_method :action,       :for_actions
    alias_method :for_action,   :for_actions
    alias_method :with_action,  :for_actions
    alias_method :with_actions, :for_actions
    
    # The kicker.  This actually sets up the configuration for the 
    # action decleration
    # :api: public
    def policy_group(label)
      raise NoForActionStatement if working_actions.empty?
      
      # Construct the configuration object
      working_actions.each do |action|
        _actions[action].action   = action
        _actions[action].label    = label
        _actions[action].target   = target_context.last
        _actions[action].options  = option_context.last
        _actions[action].activate!
        nil # End of chain
      end
      
    end
    alias_method :with_label,       :policy_group
    alias_method :label,            :policy_group
    alias_method :use_label,        :policy_group
    alias_method :use_policy_group, :policy_group
    
    # Set the authorization to be based on an instance of an object.
    # Provide a Symbol of the method name to call to get the object.
    # :api: public
    def with_target(method)
      target_context.push method
      yield
      target_context.pop
      nil # should not chain
    end
    alias_method :with_instance,  :with_target
    alias_method :target,         :with_target
    
    # Use with_options to provide options to your policies.  
    # opts <Hash|Proc> If you supply a proc as the options it will be evaluated
    # in the context of the controller
    # :api: public
    def with_options(opts)
      option_context.push opts
      yield
      option_context.pop
      nil # should not chain
    end
    alias_method :options,        :with_options
    alias_method :poilcy_options, :with_options
    
    
    class ActionManager
      # These methods are for configuration on a per action 
      # basis.  If you just want to use global level policy groups (label) just 
      # leave the target blank.
      # The label is the policy group label to use,
      # target is a symbol of the method to call to get the target object
      # :api: plugin
      attr_accessor :action, :label, :target, :options
      attr_writer   :active
      
      def initialize(action=nil, label=nil)
        @action = action.to_s
        @label  = label
      end
      
      # Make this configuration active.  By default configurations are not active!!
      # :api: plugin
      def activate!
        @active = true
      end
      
      # Check to see if this configuration is active
      # :api: plugin
      def active?
        !!@active
      end
      
      # Don't activate this one
      def clear!
        @active = false
      end
      
    end
    
  end # Controller Helper
end # Merb::Authorization