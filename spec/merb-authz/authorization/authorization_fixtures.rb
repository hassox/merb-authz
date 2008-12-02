module Authz
  class Operator
    attr_accessor :pass
    authorizable!
  end # User
  
  class TestObject
    attr_accessor :payload
    authorization do
      for_labels(:always              ).use_policies("AlwaysAllow")
      for_labels(:string_or_opts      ).use_policies("StringAsPass", "UseOptions")
      for_labels(:hash, :other_label  ).use_policies("HashWithPass")
      for_labels(:string_or_hash      ).use_policies(:string_or_opts, :hash)
      for_labels(:any                 ).use_policies(:string_or_hash, :always)
    end
  end # TestObject
  
  class Cruddy
    attr_accessor :pass
    authorization do
      for_labels(:create).use_policies("Create")
      for_labels(:read  ).use_policies("Read")
      for_labels(:update).use_policies("Update")
      for_labels(:delete).use_policies("Delete")
      for_labels(:custom).use_policies("Custom")
    end
  end
end # Authz
