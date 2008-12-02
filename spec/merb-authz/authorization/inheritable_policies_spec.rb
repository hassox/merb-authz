require File.join(File.dirname(__FILE__), "..", "..", 'spec_helper.rb')
require File.join(File.dirname(__FILE__), "policies.rb")
require File.join(File.dirname(__FILE__), "authorization_fixtures.rb")

describe "inheriting policies" do
  
  def remove_inheriting_namespace
    Object.class_eval{remove_const("AuthzInherit") if defined?(AuthzInherit)}
  end
  
  before(:each) do
    remove_inheriting_namespace
    Viking.captures.clear
    module AuthzInherit
      class Master
        authorization do
          for_label(:edit).use_policies("StringAsPass")
          for_label(:create).use_policy("HashWithPass")
          for_label(:update).use_policy("StringAsPass")
          for_label(:bar).use_policies("StringAsPass")
        end
      end # Master
      
      class Child < Master
        authorization do
          for_label(:create).use_policies("StringAsPass")
          for_label(:update).add_policies("HashWithPass")
          for_label(:foo).add_policies("AlwaysAllow")
          for_label(:bar).clear!
        end
      end # Child
    end # AuthzInherit
    
    @op = Authz::Operator.new
  end 
  
  after(:all) do
    remove_inheriting_namespace
  end
  
  
  it "should inherit it's permissions from the master" do
    AuthzInherit::Master.authorization[:edit].policies.should == AuthzInherit::Child.authorization[:edit].policies
  end
  
  it "should be able to replace the parents stragey group" do
    master = AuthzInherit::Master.authorization[:create].policy_classes
    child  = AuthzInherit::Child.authorization[:create].policy_classes
    [*master].should == [Merb::Authorization::Policies::HashWithPass]
    [*child].should  == [Merb::Authorization::Policies::StringAsPass]
  end
  
  it "should add policies to those inherited from" do
    master = AuthzInherit::Master.authorization[:update].policy_classes
    child  = AuthzInherit::Child.authorization[:update].policy_classes
    [*master].should  == [Merb::Authorization::Policies::StringAsPass]
    ([*child] - [Merb::Authorization::Policies::StringAsPass, Merb::Authorization::Policies::HashWithPass]).should be_empty
  end
  
  it "should add policies to an empty set when the parent does not yet have them defined" do
    [*AuthzInherit::Child.authorization[:foo].policy_classes].should == [Merb::Authorization::Policies::AlwaysAllow]
  end
  
  it "should be able to clear a label if required" do
    AuthzInherit::Master.authorization[:bar].policy_classes.should_not be_empty
    AuthzInherit::Child.authorization[:bar].policy_classes.should be_empty
  end  
end