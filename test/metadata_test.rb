require 'rubygems'                          
require 'active_support'
require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

class MetadataTest < Test::Unit::TestCase


  context "Metadata" do
    
    def setup
      @settings = Onelogin::Saml::Settings.new
      @settings.assertion_consumer_service_url   = "http://int.gynzy.net:8180/saml/complete"
      @settings.issuer                           = "gynzy.com" # the name of your application
      #@settings.idp_sso_target_url               = "https://aselect-s.entree.kennisnet.nl/openaselect/profiles/saml2/sso/web"
      @settings.idp_metadata                     = "https://aselect-s.entree.kennisnet.nl/openaselect/profiles/saml2/"
      @settings.idp_cert                         = "MIIEhjCCA26gAwIBAgIJAKT4P8cCZXH/MA0GCSqGSIb3DQEBBQUAMIGIMQswCQYDVQQGEwJOTDEWMBQGA1UECBMNTm9vcmQtQnJhYmFudDESMBAGA1UEBxMJRWluZGhvdmVuMQ4wDAYDVQQKEwVHeW56eTEOMAwGA1UECxMFR3luenkxDjAMBgNVBAMTBUd5bnp5MR0wGwYJKoZIhvcNAQkBFg50ZWNoQGd5bnp5LmNvbTAeFw0xMjA3MjcwNjMwNTRaFw0yMjA3MjcwNjMwNTRaMIGIMQswCQYDVQQGEwJOTDEWMBQGA1UECBMNTm9vcmQtQnJhYmFudDESMBAGA1UEBxMJRWluZGhvdmVuMQ4wDAYDVQQKEwVHeW56eTEOMAwGA1UECxMFR3luenkxDjAMBgNVBAMTBUd5bnp5MR0wGwYJKoZIhvcNAQkBFg50ZWNoQGd5bnp5LmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANEfU3B13gNvIlpX/Kp5AYTeeHpIn9AyovDmaCSuEm3TCYJEQTnpMjW6d1xzVasEeHN36RjUJQcuwKhpP1B1U/DkFziZBhKaLMHZuQJFNws+jXOadcrjBuAxsKw5bTAZFMtHF7pA1QaonwqmcdTAecI8+E6IrywQXKWAl+FCCtM09egwnjL708BxENnaikQlwmo5c34sNdQl/+RPjJS05h00nOI2g1WfVSK+2QB8d1uGfYHHfZWlFQWLrfzDnP+ChhZRJ7KnS88p5m3rHrPIxu6cd0TJAMh1XyeU2PFlPu8kbWn4Xa0aRkejseQ8BcKNevaVIxs+zxFyZ38v/ItVn0CAwEAAaOB8DCB7TAdBgNVHQ4EFgQUFEHAMjd3/4P16cF4DWwQaVw2x5wwgb0GA1UdIwSBtTCBsoAUFEHAMjd3/4P16cF4DWwQaVw2x5yhgY6kgYswgYgxCzAJBgNVBAYTAk5MMRYwFAYDVQQIEw1Ob29yZC1CcmFiYW50MRIwEAYDVQQHEwlFaW5kaG92ZW4xDjAMBgNVBAoTBUd5bnp5MQ4wDAYDVQQLEwVHeW56eTEOMAwGA1UEAxMFR3luenkxHTAbBgkqhkiG9w0BCQEWDnRlY2hAZ3luenkuY29tggkApPg/xwJlcf8wDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQUFAAOCAQEAYGr5M3lCjs2kib0dFxLJuQX5z7mOkCR9dmfriEH5bOSAn2J7BCISzuxk6Lw1cO89NpCGJYXqJuJu9lqrktJtaunIckX395vs7qW48sUXh9s/bJGxmHpf7nF3LrLyD6KpanWMxCKAUK5Q47jcz179mBE575PI1321Bz7/17hbmYo9cE0SN3KQJu0Yo/Ub+hTDFnYEMmj+WoShCjopcbdvL6gGaYChR0SMFcp14GR5T5PQIL+XhvR4beQfs8RLF5iyZNrAiBjdta4CF2GTgTYd3Uq6h/V0VLnE9PQYnlzJfhrvuYiM6yEot5FS8Xau0l8Jk6LrSGfFP1D0lGBGMHvmCw=="
      @settings.name_identifier_format           = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
      @settings.single_logout_service_url        = "http://int.gynzy.net:8180/saml/logout"
      @settings.single_logout_service_binding    = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
      @settings.contacts                         = {:technical => {:givenName => "Tim E", :emailAddress => 'time@gynzy.com'}}
    end    
    
    should "Generate SP metadata" do
      @settings = Onelogin::Saml::Settings.new      
      @settings.assertion_consumer_service_url   = "http://sp.example.com/saml/consume"
      @settings.issuer = "http://sp.example.com"
      @settings.assertion_consumer_service_binding   = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
      @settings.name_identifier_format = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
    	meta = Onelogin::Saml::Metadata.new(@settings )
    	metadata = meta.generate()
    	assert metadata == metadata_response1
    end
    
    should "Read IDP metadata" do       
      idp_metadata_response = File.read(File.join(File.dirname(__FILE__), "responses", "idp_metadata_response.xml"))    
      meta = Onelogin::Saml::Metadata.new(@settings)
      idp_metadata = meta.get_idp_metadata
      xml_compare idp_metadata_response, idp_metadata
    end
    
    should "test SingleSignOnService binding selection" do       
      meta = Onelogin::Saml::Metadata.new(@settings)
      idp_metadata = meta.get_idp_metadata
      action, content = meta.binding_select("SingleSignOnService")
      puts action
      puts content
    end
  end
end
