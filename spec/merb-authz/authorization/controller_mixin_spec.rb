require File.join(File.dirname(__FILE__), "..", "..", 'spec_helper.rb')
require File.join(File.dirname(__FILE__), "policies.rb")
require File.join(File.dirname(__FILE__), "authorization_fixtures.rb")

describe "Controller Mixin" do
  
  before(:all) do
    Merb::Config[:exception_details] = true
    clear_strategies!
    Viking.captures.clear
    Merb::Router.prepare do
      match("/crud/:action").to(:controller => "authz_crud_controller")
      match("/:action").to(:controller => "authz_controller")
    end
    
    module Merb::Authentication::Strategies
      class AcceptLogin < Merb::Authentication::Strategy
        def run!
          Viking.capture(self.class)
          user = User.new if request.params[:login]
        end
      end
    end
    Merb::Authentication.default_strategy_order = [Merb::Authentication::Strategies::AcceptLogin]
    Merb::Authorization.authorization.reset_policy_groups!
    require File.join(File.dirname(__FILE__), "controllers.rb")
  end 
  
  before(:each) do
    Viking.captures.clear
  
  end
  
  describe "Manual Controller Setup" do
    it "should login" do
      result = request("/login", :params => {:login => true}) 
      result.should be_successful
      result.body.to_s.should ==  "Logged In"
    end
  
    it "should logout" do
     request("/login", :params => {:login => true})
      result = request("/logout")
      result.should be_successful
      result.body.to_s.should == "Logged Out"
    end
  
    it "should protect an action with the specified policies" do
      request("/login", :params => {:login => true})
      result = request("/one")
      Viking.captures.should include(ran_policy?("StringAsPass"))
      result.status.should == Merb::Controller::Unauthorized.status
    end
  
    it "should allow the user access to the method if the policy is acceptable" do
      request("/login", :params => {:login => true})
      result = request("/one", :params => {:pass => "pass"})
      Viking.captures.should include(ran_policy?("StringAsPass"))
      result.should be_successful
      result.body.to_s.should == "one"
    end
  
    it "should use a target object and pass when it acceptable" do
      request("/login", :params => {:login => true})
      result = request("/two", :params => {:target => {:pass => true}})
      Viking.captures.should include(ran_policy?("HashWithPass", :instance))
      result.should be_successful
    end
  
    it "should use a target object and fail when not acceptable" do
      request("/login", :params => {:login => true})
      result = request("/two", :params => {:target => {:foo => "bar"}})
      Viking.captures.should include(ran_policy?("HashWithPass", :instance))
      result.status.should == Merb::Controller::Unauthorized.status
    end
  
    it "should protect multiple actions declared in the same statement" do
      request("/login", :params => {:login => true})
      ["two", "three"].each do |action|
        result = request("/#{action}", :params => {:target => {:foo => "bar"}})
        Viking.captures.should include(ran_policy?("HashWithPass", :instance))
        result.status.should == Merb::Controller::Unauthorized.status
      end
    end
  
    it "should protect an instance with options" do
      request("/login", :params => {:login => true})
      result = request("/with_options", :params => {:target =>  "Authz::TestObject", :options => {:pass => "pass"}})
      Viking.captures.should include(ran_policy?("UseOptions", :instance))
      result.should be_successful
      result.body.to_s.should == "{\"pass\"=>\"pass\"}"
    end
  
    it "should try to log the user in if they're not already logged in" do
      response = request("/one")
      response.status.should == Merb::Controller::Unauthenticated.status
    end
  end
  
  describe "Crud Protected Controller" do
    
    it "should require login" do
      response = request("/crud/index")
      response.status.should == Merb::Controller::Unauthenticated.status
    end
    
    it "should set the target method to :find_member" do
      AuthzCrudController.authorization[:show].target.should == :find_member
    end
    
    it "should protect the index with :read in a general sense" do
      response = request("/crud/index", :params => {:login => true})
      Viking.captures.should include(ran_policy?("Read"))
    end
    
    it "should protect the show action with :read in an instance sence" do
      response = request("/crud/show", :params => {:login => true})
      Viking.captures.should include(ran_policy?("Read", :instance))
    end
    
    it "should protect the edit action with :update in an instance sense" do
      request("/crud/edit", :params => {:login => true})
      Viking.captures.should include(ran_policy?("Update", :instance))
    end
    
    it "should protect the update action with :update in an instance sense" do
      request("/crud/update", :params => {:login => true})
      Viking.captures.should include(ran_policy?("Update", :instance))
    end
    
    it "should protect the create action with :create in a general sense" do
      request("/crud/create", :params => {:login => true})
      Viking.captures.should include(ran_policy?("Create", :general))
    end
    
    it "should protect the new action with :create in a general sense" do
      request("/crud/new", :params => {:login => true})
      Viking.captures.should include(ran_policy?("Create", :general))
    end
    
    it "should protect the delete action with :delete in an instance sense" do
      request("/crud/delete", :params => {:login => true})
      Viking.captures.should include(ran_policy?("Delete", :instance))
    end
    
    it "should protect the destroy action with :delete in an instance sense" do
      request("/crud/destroy", :params => {:login => true})
      Viking.captures.should include(ran_policy?("Delete", :instance))
    end
  end
  
end

