require File.join(File.dirname(__FILE__), "..", "..", 'spec_helper.rb')
require File.join(File.dirname(__FILE__), "policies.rb")
require File.join(File.dirname(__FILE__), "authorization_fixtures.rb")

describe "authorized?" do
  before(:all) do
    Merb::Authorization.authorization.reset_policy_groups!
    Merb::Authorization.global_policies do
      for_labels(:string                ).use_policies("StringAsPass")
      for_labels(:hash                  ).use_policies("HashWithPass")
      for_labels(:string_or_hash        ).use_policies(:string, :hash)
      for_labels(:string_or_hash_or_opts).use_policies(:string, :hash, "UseOptions")
      for_labels(:always                ).use_policies("AlwaysAllow")
    end
  end
  
  after(:all) do
    Merb::Authorization.authorization.reset_policy_groups!
    Viking.captures.clear
  end
  
  before(:each) do
    Viking.captures.clear
    @op = Authz::Operator.new
    @to = Authz::TestObject.new
  end

  describe "general_policy" do
    it "should run each policy in the policy group and return true when one passes" do
      @op.authorized?(:string_or_hash_or_opts, "pass" => true).should be_true
      Viking.captures.should include(ran_policy?("UseOptions"))
    end
  
    it "should run all policies in the policy group and return false when none pass" do
      @op.authorized?(:string_or_hash_or_opts, "pass" => false).should be_false
      ["UseOptions", "StringAsPass", "HashWithPass"].each do |pol|
        Viking.captures.should include(ran_policy?(pol))
      end
    end
  
    it "should run only the policies in the group until it finds one that passes" do
      pending
      # Can't test this bad boy with a set :(
    end
  
    it "should only run the policy once on the user and should cache the result so it doesn't run again" do
      @op.authorized?(:string_or_hash_or_opts)
      num = Viking.captures.size
      @op.authorized?(:string_or_hash_or_opts)      
      Viking.captures.size.should == num
    end
  
    it "should run the policy many times if the cache option is set to false" do 
      @op.authorized?(:string_or_hash_or_opts, :cache => false)
      num = Viking.captures.size
      @op.authorized?(:string_or_hash_or_opts, :cache => false)
      Viking.captures.size.should == num * 2
    end
    
    it "should treat policies with different options as different options as different in the cache" do
      @op.authorized?(:string_or_hash_or_opts, "pass" => true).should be_true
      first_run = Viking.captures.size
      Viking.captures.clear
      @op.authorized?(:string_or_hash_or_opts, :some => "option", "pass" => true).should be_true
      second_run = Viking.captures.size
      Viking.captures.clear
      second_run.should == first_run
      @op.authorized?(:string_or_hash_or_opts, "pass" => true).should be_true
      Viking.captures.should be_empty
    end
  end

  describe "instance_policy" do
    before(:each) do
    end
    
    it "should run each policy in the policy group and return true when one passes" do
      @op.authorized?(:string_or_hash_or_opts, :target => "pass").should be_true
      Viking.captures.should include(ran_policy?("StringAsPass", :instance))
      @op.authorized?(:string_or_hash_or_opts, :target => {:pass => true}).should be_true
      Viking.captures.should include(ran_policy?("HashWithPass", :instance))
    end
  
    it "should run all policies in the policy group and return false when none pass" do
      @op.authorized?(:string_or_hash_or_opts, :target => "foo").should be_false
      ["HashWithPass", "StringAsPass", "UseOptions"].each do |p|
        Viking.captures.should include(ran_policy?(p, :instance))
      end
    end
  
    it "should only run the policy once on the user and should cache the result so it doesn't run again" do
      @op.authorized?(:string, :target => "pass").should be_true
      Viking.captures.size.should == 1
      Viking.captures.clear
      @op.authorized?(:string, :target => "pass").should be_true
      Viking.captures.should be_blank
    end
  
    it "should run the policy many times if the cache option is set to false" do
      @op.authorized?(:string, :target => "pass", :cache => false).should be_true
      Viking.captures.size.should == 1
      Viking.captures.clear
      @op.authorized?(:string, :target => "pass", :cache => false).should be_true
      Viking.captures.size.should == 1
    end
    
    it "should not consider the cache option in they caching" do
      @op.authorized?(:string, :target => "pass").should be_true
      Viking.captures.size.should == 1
      Viking.captures.clear
      @op.authorized?(:string, :target => "pass", :cache => true).should be_true
      Viking.captures.should be_blank
    end
  end
  
end