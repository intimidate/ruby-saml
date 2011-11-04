require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

class RequestTest < Test::Unit::TestCase

  context "Authrequest" do
    should "create the deflated SAMLRequest URL parameter" do
      settings = Onelogin::Saml::Settings.new
      settings.idp_sso_target_url = "http://stuff.com"
      action, auth_url = Onelogin::Saml::Authrequest.new(settings).create
		assert_match "GET", action
		
      assert auth_url =~ /^http:\/\/stuff\.com\?SAMLRequest=/
      payload  = CGI.unescape(auth_url.split("=").last)
      decoded  = Base64.decode64(payload)

      zstream  = Zlib::Inflate.new(-Zlib::MAX_WBITS)
      inflated = zstream.inflate(decoded)
      zstream.finish
      zstream.close

      assert_match /^<samlp:AuthnRequest/, inflated
    end

    should "accept extra parameters" do
      settings = Onelogin::Saml::Settings.new
      settings.idp_sso_target_url = "http://stuff.com"

      action, auth_url = Onelogin::Saml::Authrequest.new(settings).create({ :hello => "there" })
      assert auth_url =~ /&hello=there$/

      action, auth_url = Onelogin::Saml::Authrequest.new(settings).create({ :hello => nil })
      assert auth_url =~ /&hello=$/
    end
	 
	 should "Generate HTTP-Redirect request" do
		 settings = Onelogin::Saml::Settings.new
		 settings.idp_metadata = File.expand_path(File.join(File.dirname(__FILE__), "idp-meta-redirect.xml"))
		 settings.assertion_consumer_service_url   = "http://sp.example.com/saml/consume"
		 settings.issuer = "http://sp.example.com"
		 request = Onelogin::Saml::Authrequest.new(settings)
		 action, content = request.create
		 assert action == "GET"
	 end
	 
	 should "Generate HTTP-POST request" do
		 settings = Onelogin::Saml::Settings.new
		 settings.idp_metadata = File.expand_path(File.join(File.dirname(__FILE__), "idp-meta-post.xml"))
		 settings.assertion_consumer_service_url   = "http://sp.example.com/saml/consume"
		 settings.issuer = "http://sp.example.com"
		 request = Onelogin::Saml::Authrequest.new(settings)
		 action, content = request.create
		 assert action == "POST"
	 end
  end
end
