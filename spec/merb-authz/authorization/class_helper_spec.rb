require File.join(File.dirname(__FILE__), "..", "..", 'spec_helper.rb')
require File.join(File.dirname(__FILE__), "policies.rb")
require File.join(File.dirname(__FILE__), "authorization_fixtures.rb")

describe "Setup Policy groups on a class" do
  
  def remove_test_class
    Object.class_eval{ remove_const "AuthzTester" if defined?(AuthzTester)}
  end
  
  before(:each) do
    remove_test_class
    class AuthzTester; end
  end
  
  after(:all) do
    remove_test_class
  end
  
  it "should provide a class helper instance on every class when asked" do
    AuthzTester.authorization.should be_an_instance_of(Merb::Authorization::ClassHelper)
  end
  
  describe "policy / label mapping" do
    it "should setup a policy to a label" do
      AuthzTester.authorization do
        for_label(:label1).use_policy("StringAsPass")
      end
      AuthzTester.authorization[:label1].policy_classes.should  include(Merb::Authorization::Policies::StringAsPass)
    end
    
    it "should setup a policy group on a label" do 
      AuthzTester.authorization do
        for_label(:label1).use_policy("StringAsPass", "HashWithPass")
      end
      [Merb::Authorization::Policies::StringAsPass,Merb::Authorization::Policies::HashWithPass].each do |pol|
        AuthzTester.authorization[:label1].policy_classes.should include(pol)
        AuthzTester.authorization[:label1].policy_classes.delete(pol)
      end
      AuthzTester.authorization[:label1].policy_classes.should be_empty
    end
  
    it "should raise an error if the with(:label) is not given a use" do
      lambda do
        AuthzTester.authorization do
          for_label(:label2)
          for_label(:label3).use_policy("StringAsPass")
        end
      end.should raise_error(Merb::Authorization::OpenForLabelStatement)
    end
    
    it "should raise an error if the policy has not been declared" do
      lambda do
        AuthzTester.authorization do
          for_label(:label1).use_policy("DoesNotExistPolicy")
        end
        AuthzTester.authorization[:label1].policy_classes
      end.should raise_error(Merb::Authorization::PolicyNotFound)
    end
    
    it "should setup a policy group with when refering to a label" do
      AuthzTester.authorization do
        for_label(:label1).use_policies("StringAsPass", "AlwaysAllow")
        for_label(:label2).use_policies(:label1, "HashWithPass")
      end
      [
        Merb::Authorization::Policies::StringAsPass,
        Merb::Authorization::Policies::HashWithPass,
        Merb::Authorization::Policies::AlwaysAllow
      ].each do |pol|
        AuthzTester.authorization[:label2].policy_classes.should include(pol)
        AuthzTester.authorization[:label2].policy_classes.delete(pol)
      end
      AuthzTester.authorization[:label2].policy_classes.should be_empty
    end
    
    it "should refer to the global policies when useing labels in policy groups" do
      Merb::Authorization.global_policies do
        for_label(:global).use_policy("AlwaysAllow")
      end
      AuthzTester.authorization do
        for_labels(:label1).use_policy(:global, "StringAsPass")
      end
      [
        Merb::Authorization::Policies::StringAsPass,
        Merb::Authorization::Policies::AlwaysAllow
      ].each do |pol|
        AuthzTester.authorization[:label1].policy_classes.should include(pol)
        AuthzTester.authorization[:label1].policy_classes.delete(pol)
      end
      AuthzTester.authorization[:label1].policy_classes.should be_empty
    end
    
    it "should raise an error if there is no label of that kind defined on the class or globally" do
      lambda do
        AuthzTester.authorization do
          for_label(:label1).use_policy(:does_not_exist)
        end
        AuthzTester.authorization[:label1].policy_classes
      end.should raise_error(Merb::Authorization::PolicyNotFound)
    end

  end
  
end