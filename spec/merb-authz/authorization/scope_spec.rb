require File.join(File.dirname(__FILE__), "..", "..", 'spec_helper.rb')
require File.join(File.dirname(__FILE__), "policies.rb")

describe "Policy scope" do
  
  before(:all) do
    Merb::Authorization.global_policies.reset_policy_groups!
    
    Merb::Authorization.global_policies do
      for_label(:foo).use_policy("UseOptions")
      for_label(:global).use_policy("StringAsPass", "UseOptions")
    end
    
    module AuthzScope
      class Foo
        authorization do
          for_label(:foo).use_policy("StringAsPass")
          for_label(:bar).use_policies("StringAsPass", "HashWithPass")
        end
      end # Foo
      
      class Bar
        authorization do
          copy_scope(Foo) do
            for_label(:bar).add_policies(:bar, "AlwaysAllow")
          end
        end
      end # Bar
      
      class SomethingDifferent
        authorization do
          use_scopes(Bar, Foo) do
            for_labels(:diff  ).add_policies(:foo, "AlwaysAllow")
            for_labels(:global).use_policies(:global)
          end
        end
      end # Something Different
    end # AuthzScope
  end # before :all
  
  it "should add the policies of the first class found posessing the label when using scopes" do
    [
      Merb::Authorization::Policies::AlwaysAllow,
      Merb::Authorization::Policies::HashWithPass,
      Merb::Authorization::Policies::StringAsPass,
    ].each do |policy|
      AuthzScope::Bar.authorization[:bar].policy_classes.should include(policy)
    end
    AuthzScope::Bar.authorization[:bar].policy_classes.size.should == 3
  end
  
  it "should fall back to the global scopes if no scope is found in the scoped classes" do
    [
      Merb::Authorization::Policies::StringAsPass,
      Merb::Authorization::Policies::UseOptions,
    ].each do |policy|
      AuthzScope::SomethingDifferent.authorization[:global].policy_classes.should include(policy)
    end
    AuthzScope::SomethingDifferent.authorization[:global].policy_classes.size.should == 2
  end
  
  it "should look in all classes provided as scopes for a matching label" do
    [
      Merb::Authorization::Policies::StringAsPass,
      Merb::Authorization::Policies::AlwaysAllow,
    ].each do |policy|
      AuthzScope::SomethingDifferent.authorization[:diff].policy_classes.should include(policy)
    end
    AuthzScope::SomethingDifferent.authorization[:diff].policy_classes.size.should == 2
  end  
  
end
