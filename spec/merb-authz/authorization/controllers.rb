Merb::Authorization.global_policies do
  for_label(:string).use_policy("StringAsPass")
  for_label(:hash  ).use_policy("HashWithPass")
end

class AuthzController < Merb::Controller
  before :setup_user
  
  authorization do
    for_action(:one).policy_group(:string)
        
    with_target(:get_an_object) do
      for_action(:two, :three ).policy_group(:hash)
      
      for_action(:with_target ).policy_group(:always)
      
      with_options(:get_options) do
        for_action(:with_options).policy_group(:string_or_opts)
      end
    end
  end # authorization
  
  def login
    session.user ||= User.new
    session.user.name = !params[:pass].nil? ? params[:pass] : nil 
    "Logged In"
  end
  
  def logout
    session.abandon!
    "Logged Out"
  end
  
  def one
    "one"
  end
  
  def two
    "two"
  end
  
  def three
    "three"
  end
  
  def with_target
    get_an_object.class.name
  end
  
  def with_options
    get_options.inspect
  end
  
  private 
  def get_an_object
    case params[:target]
    when nil
      nil
    when "Authz::TestObject"
      Authz::TestObject.new
    else
      params[:target]
    end
  end
  
  def get_options
    params[:options]
  end
  
  def setup_user
    if session.authenticated?
      session.user.name = params[:pass] if params[:pass]
    end
  end
  
end

class AuthzCrudController < Merb::Controller
  authorize_crud_resource Authz::Cruddy, :member_finder => :find_member do
    for_actions(:custom).policy_group(:custom)
  end
  
  def index;      "INDEX";    end
  def show;       "SHOW";     end
  def edit;       "EDIT";     end
  def update;     "UPDATE";   end
  def new;        "NEW";      end
  def create;     "CREATE";   end
  def delete;     "DELETE";   end
  def destroy;    "DESTROY";  end
  def custom;     "CUSTOM";   end
  
  private
  def find_member
    Authz::Cruddy.new
  end
  
end