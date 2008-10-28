require File.join(File.dirname(__FILE__), "..", 'spec_helper.rb')

describe Merb::Authorization, "authorizable mixin" do
  
  before(:each) do
    Capturer.captures.clear
    
    class Merb::Authorization
      module Policies
        class Policy1 < Policy
          def run!(obj, user)
            Capturer.captures << self.class
            if user.respond_to?(:pass_for)
              user if user.pass_for == self.class
            else
              false
            end
          end
       
        end
        
        class Policy2 < Policy1; end
        class Policy3 < Policy1; end
        class Policy4 < Policy1; end
      end # Policies
    end # Merb::Authorization
    
    class AuthorizableClass
      authorizable!
      
      authorize do
        with(:label1          ).use(:Policy1)
        with(:label2, :label3 ).use(:Policy2, :Policy1) 
        with(:label4          ).use(Merb::Authorization::Policies::Policy1)
        with(:proc            ).use { "In The Block" }
      end
    end
  end
  
  it{Object.should respond_to(:authorizable!)}
  
  describe "authorize_with" do

    before(:each) do
      @ac = AuthorizableClass.new
      @user = User.new
    end
    it "should authorize the user with the correct strategy" do
      @user.pass_for = MAP::Policy1
      @ac.authorized?(@user, :label1).should be_true
      Capturer.captures.should == [MAP::Policy1]
    end 
        
    it "should raise a Merb::Controller::Unauthorized if the strategy fails" do
      @user.pass_for = nil
      lambda do
        @ac.authorized?(@user, :label1)
      end.should raise_error(Merb::Controller::Unauthorized)
    end
    
    it "should cascade strategies if declared with multiple strategies" do
      @user.pass_for = MAP::Policy1
      @ac.authorized?(@user, :label2).should be_true
    end
    
    it "should allow for arrays of labels to be passed to policy groups" do
      @user.pass_for = MAP::Policy1
      @ac.authorized?(@user, :label3)
    end
    
    it "should raise an exception if all policies fail when cascading" do
      @user.pass_for = nil
      lambda do
        @ac.authorized?(@user, :label2)
      end.should raise_error(Merb::Controller::Unauthorized)
    end
    
    it "should execute a declared policy directly" do
      @user.pass_for = MAP::Policy4
      @ac.authorized?(@user, MAP::Policy3, :Policy4).should be_true
      Capturer.captures.should == [MAP::Policy3, MAP::Policy4]
    end
    
    it "should execute a mixture of lables and policies and do each one only once" do
      @user.pass_for = MAP::Policy3
      @ac.authorized?(@user, :label1, :Policy4, :label2, :Policy3)
      Capturer.captures.should == [MAP::Policy1, MAP::Policy4, MAP::Policy2, MAP::Policy3]
    end
    
    it "should raise an error if it can't find a label or policy" do
      lambda do
        @ac.authorized?(@user, :not_here)
      end.should raise_error(Merb::Authorization::PolicyNotFound)
    end
    
    it "should allow authorization from a block" do
      @ac.authorized?(@user, :proc)
    end
  
  end
  
end