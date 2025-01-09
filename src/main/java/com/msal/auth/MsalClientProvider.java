package com.msal.auth;

import com.microsoft.aad.msal4j.*;
import com.msal.config.AuthConfig;


public class MsalClientProvider {
    private static IConfidentialClientApplication clientApp;

    public static synchronized IConfidentialClientApplication getClient() throws Exception {
        if (clientApp == null) {
            clientApp = ConfidentialClientApplication.builder(
                            AuthConfig.getClientId(),
                            ClientCredentialFactory.createFromSecret(AuthConfig.getClientSecret()))
                    .authority(AuthConfig.getAuthority())
                    .build();
        }
        return clientApp;
    }

    public static String getAuthorizationCodeUrl(String state, String nonce) throws Exception {
        AuthorizationRequestUrlParameters parameters = AuthorizationRequestUrlParameters
                .builder(AuthConfig.getRedirectUri(), AuthConfig.getScopes())
                .state(state)
                .nonce(nonce)
                .responseMode(ResponseMode.QUERY)
                .prompt(Prompt.SELECT_ACCOUNT)
                .build();

        return getClient().getAuthorizationRequestUrl(parameters).toString();
    }

    public static IAuthenticationResult acquireToken(String authCode) throws Exception {
        AuthorizationCodeParameters parameters = AuthorizationCodeParameters
                .builder(authCode, new java.net.URI(AuthConfig.getRedirectUri()))
                .scopes(AuthConfig.getScopes())
                .build();

        return getClient().acquireToken(parameters).get();
    }
}
