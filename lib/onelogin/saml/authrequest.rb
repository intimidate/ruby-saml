require "base64"
require "uuid"
require "zlib"
require "cgi"
require "rexml/document"
require "rexml/xpath"
require "rubygems"
require "addressable/uri"

module Onelogin::Saml
  include REXML
  class Authrequest
	  # a few symbols for SAML class names
	  HTTP_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
	  HTTP_GET = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	  
		def initialize( settings )
			@settings = settings
			@request_params = Hash.new
		end
		
		def create(params = {})
			uuid = "_" + UUID.new.generate
			time = Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")
			# Create AuthnRequest root element using REXML 
			request_doc = REXML::Document.new
			request_doc.context[:attribute_quote] = :quote
			root = request_doc.add_element "samlp:AuthnRequest", { "xmlns:samlp" => "urn:oasis:names:tc:SAML:2.0:protocol" }
			root.attributes['ID'] = uuid
			root.attributes['IssueInstant'] = time
			root.attributes['Version'] = "2.0"

			# Conditionally defined elements based on settings
			if @settings.assertion_consumer_service_url != nil
				root.attributes["AssertionConsumerServiceURL"] = @settings.assertion_consumer_service_url
			end
			if @settings.issuer != nil
				issuer = root.add_element "saml:Issuer", { "xmlns:saml" => "urn:oasis:names:tc:SAML:2.0:assertion" }
				issuer.text = @settings.issuer
			end
      
      
      if @settings.authn_signed
        digest = Base64.encode64(Digest::SHA1.digest(uuid)).chomp
                
				signature = root.add_element "ds:Signature", { "xmlns:ds" => "http://www.w3.org/2000/09/xmldsig#" }
        signature.add_element "ds:CanonicalizationMethod", { "Algorithm" => "http://www.w3.org/2001/10/xml-exc-c14n#" }
        signature.add_element "ds:SignatureMethod", { "Algorithm" => "http://www.w3.org/2000/09/xmldsig#rsa-sha1" }
        reference = signature.add_element "Reference", { "URI" => "#{uuid}" }
        transforms = reference.add_element "Transforms"
        transforms.add_element "Transform", {"Algorithm" => "http://www.w3.org/2000/09/xmldsig#enveloped-signature"}
        transforms.add_element "Transform", {"Algorithm" => "http://www.w3.org/2001/10/xml-exc-c14n#"}
        
        reference.add_element "DigestMethod", {"Algorithm" => "http://www.w3.org/2000/09/xmldsig#rsa-sha1"}
        digest_value = reference.add_element "DigestValue"
        digest_value.text = digest
        
        
        private_key = @settings.get_private_key
        sig = private_key.sign(OpenSSL::Digest::SHA1.new, digest)
        sig = [sig].pack("m").gsub(/\n/, "")
        
        
        signed_info = signature.add_element "ds:SignedInfo"
        signature_value = signature.add_element "ds:SignatureValue"
        signature_value.text = sig
        key_info = signature.add_element "ds:keyInfo"
        x509_data = key_info.add_element "ds:X509Data"
        x509_certificate = x509_data.add_element "ds:X509Certificate"
        x509_certificate.text = @settings.get_cert
      end
      
			if @settings.name_identifier_format != nil
				root.add_element "samlp:NameIDPolicy", { 
						"xmlns:samlp" => "urn:oasis:names:tc:SAML:2.0:protocol",
						# Might want to make AllowCreate a setting?
						"AllowCreate" => "true",
						"Format" => @settings.name_identifier_format
				}
			end

			# BUG fix here -- if an authn_context is defined, add the tags with an "exact"
			# match required for authentication to succeed.  If this is not defined, 
			# the IdP will choose default rules for authentication.  (Shibboleth IdP)
			if @settings.authn_context != nil
				requested_context = root.add_element "samlp:RequestedAuthnContext", { 
					"xmlns:samlp" => "urn:oasis:names:tc:SAML:2.0:protocol",
					"Comparison" => "exact",
				}
				class_ref = requested_context.add_element "saml:AuthnContextClassRef", { 
					"xmlns:saml" => "urn:oasis:names:tc:SAML:2.0:assertion",
				}			
				class_ref.text = @settings.authn_context
			end

			@request = ""
			request_doc.write(@request)

			Logging.debug "Created AuthnRequest: #{@request}"

			#params.each_pair do |key, value|
			#  #request_params << "&#{key}=#{CGI.escape(value.to_s)}"
			#	@request_params[key] = value
			#end

			#settings.idp_sso_target_url + request_params

			# Based on the IdP metadata, select the appropriate binding 
			# and return the action to perform to the controller
			meta = Metadata.new( @settings )
			return meta.create_sso_request( @request, params )
		end
		
		# construct the the parameter list on the URL and return
		def content_get
			# compress GET requests to try and stay under that 8KB request limit
			deflated_request  = Zlib::Deflate.deflate(@request, 9)[2..-5]
			# strict_encode64() isn't available?  sub out the newlines
			@request_params["SAMLRequest"] = Base64.encode64(deflated_request).gsub(/\n/, "")
			
			Logging.debug "SAMLRequest=#{@request_params["SAMLRequest"]}"
			uri = Addressable::URI.parse(@URL)
			if uri.query_values == nil
				uri.query_values = @request_params
			else
				# solution to stevenwilkin's parameter merge
				uri.query_values = @request_params.merge(uri.query_values)
			end
			url = uri.to_s
			#url = @URL + "?SAMLRequest=" + @request_params["SAMLRequest"]
			Logging.debug "Sending to URL #{url}"
			return url
		end
		# construct an HTML form (POST) and return the content
		def content_post
			# POST requests seem to bomb out when they're deflated
			# and they probably don't need to be compressed anyway
			@request_params["SAMLRequest"] = Base64.encode64(@request).gsub(/\n/, "")
			
			#Logging.debug "SAMLRequest=#{@request_params["SAMLRequest"]}"
			# kind of a cheesy method of building an HTML, form since we can't rely on Rails too much,
			# and REXML doesn't work well with quote characters
			str = "<html><body onLoad=\"document.getElementById('form').submit();\">\n"
			str += "<form id='form' name='form' method='POST' action=\"#{@URL}\">\n"
			# we could change this in the future to associate a temp auth session ID
			str += "<input name='RelayState' value='ruby-saml' type='hidden' />\n"
			@request_params.each_pair do |key, value|
				str += "<input name=\"#{key}\" value=\"#{value}\" type='hidden' />\n"
				#str += "<input name=\"#{key}\" value=\"#{CGI.escape(value)}\" type='hidden' />\n"
			end
			str += "</form></body></html>\n"
			
			Logging.debug "Created form:\n#{str}"
			return str
		end
  end
end
