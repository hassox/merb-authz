class Object
  # @api private
  class_inheritable_accessor :_authorization
  
  # DOX NEEDED HERE
  # Use this method to make this class into 
  # and "operator". This allows instances of the class to be asked if 
  # they are authorized?
  def self.authorizable!
    include Merb::Authorization::OperatorMixin
  end
  
  # DOX NEEDED HERE
  # Use this to setup your object to allow for authorization
  # This will allow you to setup labels on your object 
  # and assign policies to them 
  # :api: public
  def self.authorization(&block)
    self._authorization ||= Merb::Authorization::ClassHelper.new
    if block_given?
      self._authorization.klass = self
      self._authorization.instance_eval(&block)
    end
    self._authorization
  end

end