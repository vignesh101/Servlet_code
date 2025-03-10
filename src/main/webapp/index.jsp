package com.fiserv.radm.service;
import com.microsoft.aad.msal4j.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
@Service
public class MsalAuthService {
    private static final Logger logger = LoggerFactory.getLogger(MsalAuthService.class);
    @Value("${azure.ad.client-id}")
    private String clientId;
    @Value("${azure.ad.client-secret}")
    private String clientSecret;
    @Value("${azure.ad.tenant-id}")
    private String tenantId;
    @Value("${azure.ad.redirect-uri}")
    private String redirectUri;
    private static final Set<String> DEFAULT_SCOPES = new HashSet<String>() {{
        add("User.Read");
        add("profile");
        add("email");
        add("openid");
    }};
    public IConfidentialClientApplication buildConfidentialClientApplication() {
        try {
            return ConfidentialClientApplication.builder(
                    clientId,
                    ClientCredentialFactory.createFromSecret(clientSecret))
                    .authority("https://login.microsoftonline.com/" + tenantId)
                    .build();
        } catch (Exception e) {
            logger.error("Error building confidential client application", e);
            throw new RuntimeException("Failed to build MSAL application", e);
        }
    }
    public String getAuthorizationUrl(String state, String nonce) {
        try {
            IConfidentialClientApplication app = buildConfidentialClientApplication();
            AuthorizationRequestUrlParameters parameters = AuthorizationRequestUrlParameters
                    .builder(redirectUri, DEFAULT_SCOPES)
                    .state(state)  // Will be returned to your app for validation
                    .nonce(nonce)  // Will be included in the ID token for validation
                    .responseMode(ResponseMode.FORM_POST)  // How Azure AD should return the response
                    .prompt(Prompt.SELECT_ACCOUNT)  // Forces the user to select an account
                    .build();
            return app.getAuthorizationRequestUrl(parameters).toString();
        } catch (Exception e) {
            logger.error("Error generating authorization URL", e);
            throw new RuntimeException("Failed to generate authorization URL", e);
        }
    }
    public IAuthenticationResult acquireTokenByAuthorizationCode(String authorizationCode) {
        try {
            IConfidentialClientApplication app = buildConfidentialClientApplication();
            AuthorizationCodeParameters parameters = AuthorizationCodeParameters
                    .builder(authorizationCode, new URI(redirectUri))
                    .scopes(DEFAULT_SCOPES)
                    .build();
            // Execute the token request
            CompletableFuture<IAuthenticationResult> future = app.acquireToken(parameters);
            return future.get();  // Blocking call to wait for the token
        } catch (ExecutionException | InterruptedException | URISyntaxException e) {
            logger.error("Error acquiring token by authorization code", e);
            throw new RuntimeException("Failed to acquire token", e);
        }
    }
    public String getEmailFromAuthenticationResult(IAuthenticationResult result) {
        if (result == null || result.account() == null) {
            return null;
        }
        return result.account().username();
    }
} 
