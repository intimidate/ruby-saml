module Onelogin::Saml
class Metadata
  class RailsCache
    
    def read(id)
      document = Rails.cache.read(id)
      unless document.nil?()
        return document.file
      end
      return nil
    end
    
    def write(id, file, expiration)
      document = Document.new(id, file, Time.now + expiration)
      Rails.cache.write(id, document, :expires_in => document.expires_in)
    end
  end
end  
class IdpMetadata
  class RailsCache
    
    def read(id)
      document = Rails.cache.read(id)
      unless document.nil?()
        return document.file
      end
      return nil
    end
    
    def write(id, file, expiration)
      document = Document.new(id, file, Time.now + expiration)
      Rails.cache.write(id, document, :expires_in => document.expires_in)
    end
  end
end 
end