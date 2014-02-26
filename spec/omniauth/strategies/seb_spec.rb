require 'spec_helper'

describe OmniAuth::Strategies::Seb do

  PRIVATE_KEY_FILE = File.join RSpec.configuration.cert_folder, "request.private.pem"
  PUBLIC_KEY_FILE = File.join RSpec.configuration.cert_folder, "response.public.pem"

  let(:app){ Rack::Builder.new do |b|
    b.use Rack::Session::Cookie, {:secret => "abc123"}
    b.use(OmniAuth::Strategies::Seb, PRIVATE_KEY_FILE, PUBLIC_KEY_FILE, "MY_SND_ID", "MY_REC_ID")
    b.run lambda{|env| [404, {}, ['Not Found']]}
  end.to_app }

  let(:private_key) { OpenSSL::PKey::RSA.new(File.read(PRIVATE_KEY_FILE)) }
  let(:public_key) { OpenSSL::PKey::RSA.new(File.read(PUBLIC_KEY_FILE)) }
  # let(:last_response_nonce) { last_response.body.match(/name="VK_NONCE" value="([^"]*)"/)[1] }
  let(:last_response_crc) { last_response.body.match(/name="IB_CRC" value="([^"]*)"/)[1] }

  context "request phase" do
    EXPECTED_VALUES = {
      "IB_SND_ID" => "MY_SND_ID",
      "IB_SERVICE" => "0005"
    }

    before(:each){ get '/auth/seb' }

    it "displays a single form" do
      expect(last_response.status).to eq(200)
      expect(last_response.body.scan('<form').size).to eq(1)
    end

    it "has JavaScript code to submit the form after it's created" do
      expect(last_response.body).to be_include("</form><script type=\"text/javascript\">document.forms[0].submit();</script>")
    end

    EXPECTED_VALUES.each_pair do |k,v|
      it "has hidden input field #{k} => #{v}" do
        expect(last_response.body.scan(
          "<input type=\"hidden\" name=\"#{k}\" value=\"#{v}\"").size).to eq(1)
      end
    end

    it "has a correct IB_CRC signature" do
      sig_str =
        "009MY_SND_ID" + # IB_SND_ID
        "0040005" # IB_SERVICE
      expected_crc = Base64.encode64(private_key.sign(OpenSSL::Digest::SHA1.new, sig_str))
      expect(last_response_crc).to eq(expected_crc)
    end

    context "with default options" do
      it "has the default action tag value" do
        expect(last_response.body).to be_include("action='https://ibanka.seb.lv/ipc/epakindex.jsp'")
      end
    end

    context "with custom options" do
      let(:app){ Rack::Builder.new do |b|
        b.use Rack::Session::Cookie, {:secret => "abc123"}
        b.use(OmniAuth::Strategies::Seb, PRIVATE_KEY_FILE, PUBLIC_KEY_FILE, "MY_SND_ID", "MY_REC_ID",
          :site => "https://test.lv/banklink")
        b.run lambda{|env| [404, {}, ['Not Found']]}
      end.to_app }

      it "has the custom action tag value" do
        expect(last_response.body).to be_include("action='https://test.lv/banklink'")
      end
    end

    context "with non-existant private key files" do
      let(:app){ Rack::Builder.new do |b|
        b.use Rack::Session::Cookie, {:secret => "abc123"}
        b.use(OmniAuth::Strategies::Seb, "missing-private-key-file.pem", PUBLIC_KEY_FILE, "MY_SND_ID", "MY_REC_ID")
        b.run lambda{|env| [404, {}, ['Not Found']]}
      end.to_app }

      it "redirects to /auth/failure with appropriate query params" do
        expect(last_response.status).to eq(302)
        expect(last_response.headers["Location"]).to eq("/auth/failure?message=private_key_load_err&strategy=seb")
      end
    end
  end

  context "callback phase" do
    let(:auth_hash){ last_request.env['omniauth.auth'] }

    context "with valid response" do
      before do
        post :'/auth/seb/callback',
          "IB_SND_ID" =>     "SEBUB", 
          "IB_SERVICE" =>    "0001", 
          "IB_REC_ID" =>     "LVTC", 
          "IB_USER" =>       "123456-12345", 
          "IB_DATE" =>       "26.02.2014", 
          "IB_TIME" =>       "13:53:31", 
          "IB_USER_INFO" =>  "ID=123456-12345;NAME=Example User", 
          "IB_VERSION" =>    "001", 
          "IB_CRC" =>        "mhhe3ipEuqDtEvz75hfIuoMDzitgELbEnVLe0g+QK9MW70bKxds0NSUvZVppN6f1SA3QJ47TqTE8tdgmun9qnHwXXI5XZfKTLM0l0C7jets56DEVKJBcvrINHse9qygPetG5zDCyCNMsAk4tKkOxhcHxtqgo7UAfCWzzRHtvc1TSYkxJqHZiDr+lp0GodrMXyNoGth0FOWrAiF07eSYJnHAUicnQSnFnmfH8vYgadZQs6sz43+i9LLBBGTPwpeC4JLyV3B1VYARPjgLwiJ1aA6Lx1aLsOmFbTb8fUM3Wfxj0J3TNf6YEJsiSC1/YdtCvuF61VTeJaEPIDCQWIho5Nw==", 
          "IB_LANG" =>       "LAT"
      end

      it "sets the correct uid value in the auth hash" do
        expect(auth_hash.uid).to eq("123456-12345")
      end

      it "sets the correct info.full_name value in the auth hash" do
        expect(auth_hash.info.full_name).to eq("Example User")
      end
    end

    context "with non-existant public key file" do
      let(:app){ Rack::Builder.new do |b|
        b.use Rack::Session::Cookie, {:secret => "abc123"}
        b.use(OmniAuth::Strategies::Seb, PRIVATE_KEY_FILE, "missing-public-key-file.pem", "MY_SND_ID", "MY_REC_ID")
        b.run lambda{|env| [404, {}, ['Not Found']]}
      end.to_app }

      it "redirects to /auth/failure with appropriate query params" do
        post :'/auth/seb/callback' # Params are not important, because we're testing public key loading
        expect(last_response.status).to eq(302)
        expect(last_response.headers["Location"]).to eq("/auth/failure?message=public_key_load_err&strategy=seb")
      end
    end

    context "with invalid response" do

      it "detects invalid signature" do
        post :'/auth/seb/callback',
          "IB_SND_ID" =>    "HP",
          "IB_SERVICE" =>   '0001',
          "IB_REC_ID" =>    "MY_REC_ID",
          "IB_USER" =>      "123456-12345",
          "IB_DATE" =>      "26.02.2014",
          "IB_TIME" =>      "10:31:43",
          "IB_USER_INFO" => 'ID=123456-12345;NAME=Example User',
          "IB_VERSION" =>   '001',
          "IB_CRC" =>       'invalid signature',
          "IB_LANG" =>      "LAT"

        expect(last_response.status).to eq(302)
        expect(last_response.headers["Location"]).to eq("/auth/failure?message=invalid_response_signature_err&strategy=seb")
      end

      it "detects unsupported VK_SERVICE values" do
        post :'/auth/seb/callback',
          "IB_SND_ID"=>"SEBUB", 
          "IB_SERVICE"=>"0009", 
          "IB_REC_ID"=>"LVTC", 
          "IB_USER"=>"123456-12345", 
          "IB_DATE"=>"26.02.2014", 
          "IB_TIME"=>"13:53:31", 
          "IB_USER_INFO"=>"ID=123456-12345;NAME=Example User", 
          "IB_VERSION"=>"001", 
          "IB_CRC"=>"mhhe3ipEuqDtEvz75hfIuoMDzitgELbEnVLe0g+QK9MW70bKxds0NSUvZVppN6f1SA3QJ47TqTE8tdgmun9qnHwXXI5XZfKTLM0l0C7jets56DEVKJBcvrINHse9qygPetG5zDCyCNMsAk4tKkOxhcHxtqgo7UAfCWzzRHtvc1TSYkxJqHZiDr+lp0GodrMXyNoGth0FOWrAiF07eSYJnHAUicnQSnFnmfH8vYgadZQs6sz43+i9LLBBGTPwpeC4JLyV3B1VYARPjgLwiJ1aA6Lx1aLsOmFbTb8fUM3Wfxj0J3TNf6YEJsiSC1/YdtCvuF61VTeJaEPIDCQWIho5Nw==", 
          "IB_LANG"=>"LAT"

        expect(last_response.status).to eq(302)
        expect(last_response.headers["Location"]).to eq("/auth/failure?message=unsupported_response_service_err&strategy=seb")
      end

      it "detects unsupported VK_VERSION values" do
        post :'/auth/seb/callback',
          "IB_SND_ID"=>"SEBUB", 
          "IB_SERVICE"=>"0001", 
          "IB_REC_ID"=>"LVTC", 
          "IB_USER"=>"123456-12345", 
          "IB_DATE"=>"26.02.2014", 
          "IB_TIME"=>"13:53:31", 
          "IB_USER_INFO"=>"ID=123456-12345;NAME=Example User", 
          "IB_VERSION"=>"008", 
          "IB_CRC"=>"mhhe3ipEuqDtEvz75hfIuoMDzitgELbEnVLe0g+QK9MW70bKxds0NSUvZVppN6f1SA3QJ47TqTE8tdgmun9qnHwXXI5XZfKTLM0l0C7jets56DEVKJBcvrINHse9qygPetG5zDCyCNMsAk4tKkOxhcHxtqgo7UAfCWzzRHtvc1TSYkxJqHZiDr+lp0GodrMXyNoGth0FOWrAiF07eSYJnHAUicnQSnFnmfH8vYgadZQs6sz43+i9LLBBGTPwpeC4JLyV3B1VYARPjgLwiJ1aA6Lx1aLsOmFbTb8fUM3Wfxj0J3TNf6YEJsiSC1/YdtCvuF61VTeJaEPIDCQWIho5Nw==", 
          "IB_LANG"=>"LAT"

        expect(last_response.status).to eq(302)
        expect(last_response.headers["Location"]).to eq("/auth/failure?message=unsupported_response_version_err&strategy=seb")
      end

    end
  end
end