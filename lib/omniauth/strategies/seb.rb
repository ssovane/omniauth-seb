require 'omniauth'
require 'base64'

class String
  def prepend_length
    # prepend length to string in 0xx format

    [ self.to_s.length.to_s.rjust(3, '0'), self.dup.to_s.force_encoding("ascii")].join
  end
end

module OmniAuth
  module Strategies
    class Seb

      include OmniAuth::Strategy

      AUTH_SERVICE_ID = "0005"

      args [:private_key_file, :public_key_file, :snd_id, :rec_id]

      option :private_key_file, nil
      option :public_key_file, nil
      option :snd_id, nil
      option :rec_id, nil

      option :name, "seb"
      option :site, "https://ibanka.seb.lv/ipc/epakindex.jsp"

      def callback_url
        full_host + script_name + callback_path
      end

      def signature(priv_key)
        Base64.encode64(priv_key.sign(OpenSSL::Digest::SHA1.new, signature_input))
      end

      def signature_input
        # return if AUTH_SERVICE_ID != "0005"
        [options.snd_id, AUTH_SERVICE_ID].map(&:prepend_length).join
      end

      uid do
        request.params["IB_USER_INFO"].match(/ID=(\d{6}\-\d{5})/)[1]
      end

      info do
        {
          :full_name => request.params["IB_USER_INFO"].match(/NAME=(.+)/)[1]
        }
      end

      def callback_phase
        begin
          pub_key = OpenSSL::X509::Certificate.new(File.read(options.public_key_file || "")).public_key
        rescue => e
          return fail!(:public_key_load_err, e)
        end
        
        if request.params["IB_SERVICE"] != "0001"
          return fail!(:unsupported_response_service_err)
        end

        if request.params["IB_VERSION"] != "001"
          return fail!(:unsupported_response_version_err)
        end

        sig_str = [
          request.params["IB_SND_ID"],
          request.params["IB_SERVICE"],
          request.params["IB_REC_ID"],
          request.params["IB_USER"],
          request.params["IB_DATE"],
          request.params["IB_TIME"],
          request.params["IB_USER_INFO"],
          request.params["IB_VERSION"]
        ].map(&:prepend_length).join

        raw_signature = Base64.decode64(request.params["IB_CRC"])

        unless pub_key.verify(OpenSSL::Digest::SHA1.new, raw_signature, sig_str)
          return fail!(:invalid_response_signature_err)
        end

        super
      rescue => e
        fail!(:unknown_callback_err, e)
      end

      def request_phase
        begin
          priv_key = OpenSSL::PKey::RSA.new(File.read(options.private_key_file || ""))
        rescue => e
          return fail!(:private_key_load_err, e)
        end

        OmniAuth.config.form_css = nil
        form = OmniAuth::Form.new(:title => I18n.t("omniauth.seb.please_wait"), :url => options.site)
 
        {
          "IB_SND_ID" => options.snd_id,
          "IB_SERVICE" => AUTH_SERVICE_ID,
          "IB_LANG" => "LAT",
          "IB_CRC" => signature(priv_key)
        }.each do |name, val|
          form.html "<input type=\"hidden\" name=\"#{name}\" value=\"#{val}\" />"
        end

        form.button I18n.t("omniauth.seb.click_here_if_not_redirected")

        form.instance_variable_set("@html",
          form.to_html.gsub("</form>", "</form><script type=\"text/javascript\">document.forms[0].submit();</script>"))
        form.to_response
      rescue => e
        fail!(:unknown_request_err, e)
      end
    end
  end
end
