package com.msal.filters;

import org.springframework.web.filter.OncePerRequestFilter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class CacheControlFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                                   FilterChain filterChain) throws ServletException, IOException {
        // Set no-cache headers for all pages
        response.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
        response.setHeader("Pragma", "no-cache");
        response.setHeader("Expires", "0");
        
        filterChain.doFilter(request, response);
    }
}


try {
    // Modify the redirect URL based on whether this was a token expiration
    String redirectUri = isTokenExpired ? 
        postLogoutRedirectUri.replace("?logout=true", "?expired=true") : 
        postLogoutRedirectUri;
            
    String encodedRedirectUri = URLEncoder.encode(redirectUri, StandardCharsets.UTF_8.toString());

    // Start with the base logout URL
    StringBuilder logoutUrl = new StringBuilder(logoutUri);
    logoutUrl.append("?post_logout_redirect_uri=").append(encodedRedirectUri);
    
    // Add login_hint parameter if we have the user's email
    if (userEmail != null && !userEmail.isEmpty()) {
        logoutUrl.append("&login_hint=")
                .append(URLEncoder.encode(userEmail, StandardCharsets.UTF_8.toString()));
        // Add prompt=select_account to ensure only this user's account is shown
        logoutUrl.append("&prompt=select_account");
        DebugLogger.log("Added login_hint and prompt=select_account to logout URL for user: " + userEmail);
    }

    DebugLogger.log("Redirecting to logout URL: " + logoutUrl);
    response.sendRedirect(logoutUrl.toString());
}


package com.msal.filters;

import com.msal.log.DebugLogger;
import com.msal.model.UserProfile;

import org.springframework.web.filter.OncePerRequestFilter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.time.Instant;

public class TokenExpirationFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // Skip checking the logout URL itself to avoid redirect loops
        String requestPath = request.getRequestURI();
        if (requestPath.startsWith(request.getContextPath() + "/logout")) {
            filterChain.doFilter(request, response);
            return;
        }

        HttpSession session = request.getSession(false);

        if (session != null) {
            UserProfile userProfile = (UserProfile) session.getAttribute("userInfo");

            if (userProfile != null && userProfile.getTokenExpirationTime() > 0) {
                long tokenExpirationTime = userProfile.getTokenExpirationTime();
                long currentTime = Instant.now().getEpochSecond();

                if (currentTime >= tokenExpirationTime) {
                    DebugLogger.log("Token has expired for user: " + userProfile.getName() + ". Redirecting to logout endpoint.");
                    
                    // Store the fact that this is a token expiration in the session
                    // so CustomLogoutHandler can use this information
                    session.setAttribute("logout_reason", "token_expired");
                    
                    // Redirect to the logout endpoint - your CustomLogoutHandler will handle the rest
                    response.sendRedirect(request.getContextPath() + "/logout");
                    return;
                }

                // Update the remaining time in the user profile
                long remainingSeconds = tokenExpirationTime - currentTime;
                userProfile.setTokenExpiresInMinutes((int)Math.ceil(remainingSeconds / 60.0));
            }
        }

        filterChain.doFilter(request, response);
    }
}


package com.msal.filters;

import com.microsoft.aad.msal4j.IAccount;
import com.microsoft.aad.msal4j.IConfidentialClientApplication;
import com.msal.log.DebugLogger;
import com.msal.model.UserProfile;
import com.msal.service.MsalService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Set;

@Component
public class CustomLogoutHandler extends SimpleUrlLogoutSuccessHandler {

    @Autowired
    private MsalService msalService;

    @Value("${azure.ad.logout-uri}")
    private String logoutUri;

    @Value("${azure.ad.post-logout-redirect-uri}")
    private String postLogoutRedirectUri;

    public CustomLogoutHandler() {
        setDefaultTargetUrl("/auth/login?logout=true");
    }

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response,
                                Authentication authentication) throws IOException, ServletException {
        DebugLogger.log("Logout initiated");

        // Get the current user's email for login_hint
        String userEmail = null;
        HttpSession session = request.getSession(false);
        
        // Check if this logout was due to token expiration
        boolean isTokenExpired = false;
        
        if (session != null) {
            UserProfile userProfile = (UserProfile) session.getAttribute("userInfo");
            if (userProfile != null) {
                userEmail = userProfile.getName();
                DebugLogger.log("Found user email for logout: " + userEmail);
            }
            
            // Check if this logout was triggered due to token expiration
            String logoutReason = (String) session.getAttribute("logout_reason");
            if (logoutReason != null && logoutReason.equals("token_expired")) {
                isTokenExpired = true;
                DebugLogger.log("Logout initiated due to token expiration");
            }
        }

        // 1. Clear MSAL tokens from cache first
        try {
            IConfidentialClientApplication client = msalService.getClient();
            Set<IAccount> accounts = client.getAccounts().join();
            DebugLogger.log("Found " + accounts.size() + " accounts in cache to remove");

            for (IAccount account : accounts) {
                DebugLogger.log("Removing account: " + account.homeAccountId());
                client.removeAccount(account).join();
            }
        } catch (Exception e) {
            DebugLogger.log("Error clearing MSAL cache: " + e.getMessage());
        }

        // 2. Clear all cookies
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                DebugLogger.log("Clearing cookie: " + cookie.getName());
                cookie.setValue("");
                cookie.setPath("/");
                cookie.setMaxAge(0);
                response.addCookie(cookie);
            }
        }

        // 3. Clear and invalidate session
        if (session != null) {
            session.removeAttribute("userInfo");
            session.removeAttribute("auth_state");
            session.removeAttribute("auth_nonce");
            session.removeAttribute("logout_reason");
            session.invalidate();
            DebugLogger.log("Session invalidated");
        }

        // 4. Build the correct logout URL with login_hint if available
        try {
            // Modify the redirect URL based on whether this was a token expiration
            String redirectUri = isTokenExpired ? 
                postLogoutRedirectUri.replace("?logout=true", "?expired=true") : 
                postLogoutRedirectUri;
                
            String encodedRedirectUri = URLEncoder.encode(redirectUri, StandardCharsets.UTF_8.toString());

            // Start with the base logout URL
            StringBuilder logoutUrl = new StringBuilder(logoutUri);
            logoutUrl.append("?post_logout_redirect_uri=").append(encodedRedirectUri);
            
            // Add login_hint parameter if we have the user's email
            if (userEmail != null && !userEmail.isEmpty()) {
                logoutUrl.append("&login_hint=")
                        .append(URLEncoder.encode(userEmail, StandardCharsets.UTF_8.toString()));
                DebugLogger.log("Added login_hint to logout URL for user: " + userEmail);
            }

            DebugLogger.log("Redirecting to logout URL: " + logoutUrl);
            response.sendRedirect(logoutUrl.toString());
        } catch (Exception e) {
            DebugLogger.log("Error during logout redirect: " + e.getMessage());
            // Fall back to local logout - use the appropriate URL based on logout reason
            if (isTokenExpired) {
                response.sendRedirect(request.getContextPath() + "/auth/login?expired=true");
            } else {
                response.sendRedirect(request.getContextPath() + "/auth/login?logout=true");
            }
        }
    }
}
