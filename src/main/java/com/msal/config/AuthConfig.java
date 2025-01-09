package com.msal.config;

import java.util.Set;

public class AuthConfig {

    private static final String CLIENT_ID = "";
    private static final String CLIENT_SECRET = "";
    private static final String TENANT_ID = "";
    private static final String AUTHORITY = "https://login.microsoftonline.com/" + TENANT_ID + "/";
    private static     final String REDIRECT_URI = "http://localhost:8080/login/oauth2/code/";

    // Scopes for Microsoft Graph API
    private static final Set<String> SCOPES = Set.of(
            "User.Read",
            "profile",
            "email"
    );

    // State and PKCE for security
    private static final int STATE_LENGTH = 32;
    private static final int PKCE_LENGTH = 64;

    public static String getClientId() {
        return CLIENT_ID;
    }

    public static String getClientSecret() {
        return CLIENT_SECRET;
    }

    public static String getAuthority() {
        return AUTHORITY;
    }

    public static String getRedirectUri() {
        return REDIRECT_URI;
    }

    public static Set<String> getScopes() {
        return SCOPES;
    }

    public static String generateState() {
        return generateSecureString(STATE_LENGTH);
    }

    public static String generatePkce() {
        return generateSecureString(PKCE_LENGTH);
    }

    private static String generateSecureString(int length) {
        byte[] bytes = new byte[length];
        new java.security.SecureRandom().nextBytes(bytes);
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

}
