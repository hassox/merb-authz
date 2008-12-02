class Merb::AbstractController
  
  # Implements CRUD authorization for controllers.  You must provide it the resource to
  # use to work on.  This resource should have :create, :read, :update, and :delete policy
  # groups setup.
  #
  # Example
  # 
  # class Articles < Application
  #   authorize_crud_resource Article
  #
  #   private
  #   def find_member
  #     @article = Article.get(params[:id])
  #   end
  # end
  #
  # :api: public
  def self.authorize_crud_resource(klass, opts = {}, &block)
    @_authorization_klass = klass
    
    member_finder = opts.fetch(:member_finder, :find_member)
    config = {
        :new      => [:create,  klass,          opts[:options]],
        :create   => [:create,  klass,          opts[:options]],
        :index    => [:read,    klass,          opts[:options]],
        :show     => [:read,    member_finder,  opts[:options]],
        :edit     => [:update,  member_finder,  opts[:options]],
        :update   => [:update,  member_finder,  opts[:options]],
        :delete   => [:delete,  member_finder,  opts[:options]],
        :destroy  => [:delete,  member_finder,  opts[:options]]
      }
    config.each do |k,v|
      authorization[k].action   = k
      authorization[k].label    = v[0]
      authorization[k].target   = v[1]
      authorization[k].options  = v[2]
      authorization[k].activate!
    end
    
    authorization.target_context.push klass
    authorization.option_context.push opts[:options] if opts[:options]
    authorization.instance_eval(&block) if block_given?
    authorization
  end
end # Merb::AbstractController