require File.join(File.dirname(__FILE__), "..", "..", 'spec_helper.rb')
require File.join(File.dirname(__FILE__), "policies.rb")
require File.join(File.dirname(__FILE__), "authorization_fixtures.rb")

describe "Authorization" do
  
  before(:each) do
    Viking.captures.clear
    @op = Authz::Operator.new
  end
  
  after(:all) do
    Viking.captures.clear
  end
  
  describe "operator mixin" do
    
    it "should add 'Operator'#authorized?" do
      @op.should respond_to(:authorized?)
    end
    
    it "should add a caching object" do
      @op.auth_cache.should be_a_kind_of(Merb::Authorization::OperatorCache)
    end
    
  end # Operator mixin
end # Authorization