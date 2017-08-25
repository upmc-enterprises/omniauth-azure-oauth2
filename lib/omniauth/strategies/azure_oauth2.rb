require 'omniauth/strategies/oauth2'
require 'jwt'

module OmniAuth
  module Strategies
    class AzureOauth2  < OmniAuth::Strategies::OAuth2
      BASE_AZURE_URL = 'https://login.microsoftonline.com'

      option :name, 'azure_oauth2'

      option :tenant_provider, nil

      # AD resource identifier
      option :resource, '00000002-0000-0000-c000-000000000000'

      # tenant_provider must return aad_client_id, aad_client_secret and optionally aad_tenant_id and base_azure_url
      args [:tenant_provider]

      def client
        if options.tenant_provider
          provider = options.tenant_provider.new(self)
        else
          provider = options  # if pass has to config, get mapped right on to options
        end

        options.client_id = provider.aad_client_id
        options.client_secret = provider.aad_client_secret
        options.aad_tenant_id =
          provider.respond_to?(:aad_tenant_id) ? provider.aad_tenant_id : 'common'
        options.base_azure_url =
          provider.respond_to?(:base_azure_url) ? provider.base_azure_url : BASE_AZURE_URL

        options.authorize_params.aad_domain_hint = provider.aad_domain_hint if provider.respond_to?(:aad_domain_hint) && provider.aad_domain_hint
        options.authorize_params.prompt = request.params['prompt'] if request.params['prompt']
        options.client_options.authorize_url = "#{options.base_azure_url}/#{options.aad_tenant_id}/oauth2/authorize"
        options.client_options.token_url = "#{options.base_azure_url}/#{options.aad_tenant_id}/oauth2/token"

        options.token_params.resource = options.resource
        super
      end

      uid {
        raw_info['sub']
      }

      info do
        {
          name: raw_info['name'],
          nickname: raw_info['unique_name'],
          first_name: raw_info['given_name'],
          last_name: raw_info['family_name'],
          email: raw_info['email'] || raw_info['upn'],
          oid: raw_info['oid'],
          tid: raw_info['tid'],
          aud: raw_info['aud'],
          groups: raw_info['groups']
        }
      end

      def callback_url
        full_host + script_name + callback_path
      end

      def raw_info
        # it's all here in JWT http://msdn.microsoft.com/en-us/library/azure/dn195587.aspx
        # Groups (along with all other data) are in the id_token so we will decode this
        @raw_info ||= ::JWT.decode(access_token.params['id_token'], nil, false).first
      end

    end
  end
end
