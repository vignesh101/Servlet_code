 boolean tokenExpired = false;
        HttpSession session = request.getSession(false);
        if (session != null) {
            Object expiredObj = session.getAttribute("token_expired");
            if (expiredObj != null && expiredObj instanceof Boolean) {
                tokenExpired = (Boolean) expiredObj;
            }
        }


// 4. Build the correct logout URL with Azure AD
        try {
            // Add the token expiration parameter to the post-logout redirect URI if needed
            String redirectUri = postLogoutRedirectUri;
            if (tokenExpired) {
                // Check if the URI already has parameters
                redirectUri += (redirectUri.contains("?") ? "&" : "?") + SESSION_EXPIRED_PARAM;
            }
            
            String encodedRedirectUri = URLEncoder.encode(redirectUri, StandardCharsets.UTF_8.toString());

            String logoutUrl = logoutUri + "?post_logout_redirect_uri=" + encodedRedirectUri;

            DebugLogger.log("Redirecting to logout URL: " + logoutUrl);
            response.sendRedirect(logoutUrl);
        } catch (Exception e) {
            DebugLogger.log("Error during logout redirect: " + e.getMessage());
            // Fall back to local logout
            String redirectUrl = request.getContextPath() + "/auth/login?";
            redirectUrl += tokenExpired ? SESSION_EXPIRED_PARAM : "logout=true";
            response.sendRedirect(redirectUrl);
        }


try {
                        customLogoutHandler.onLogoutSuccess(
                            request, 
                            response, 
                            SecurityContextHolder.getContext().getAuthentication()
                        );
                        // The logout handler will handle the redirect, so we return here
                        return;
                    } catch (Exception e) {
                        DebugLogger.log("Error during automatic logout: " + e.getMessage());
                        // If there's an error in the logout process, fall back to the original behavior
                        session.invalidate();
                        response.sendRedirect(request.getContextPath() + "/auth/login?expired=true");
                        return;
                    }


// In CustomLogoutHandler.java, update the onLogoutSuccess method:

@Override
public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response,
                           Authentication authentication) throws IOException, ServletException {
    DebugLogger.log("Logout handler executing for URL: " + request.getRequestURI());
    
    // Add no-cache headers
    response.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
    response.setHeader("Pragma", "no-cache");
    response.setHeader("Expires", "0");
    
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
            DebugLogger.log("Logout was triggered due to token expiration");
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
        // Create dynamic redirect URI based on request
        String baseUrl = request.getScheme() + "://" + request.getServerName();
        if (request.getServerPort() != 80 && request.getServerPort() != 443) {
            baseUrl += ":" + request.getServerPort();
        }
        
        String appPath = request.getContextPath();
        String redirectParam = isTokenExpired ? "?expired=true" : "?logout=true";
        String redirectUri = baseUrl + appPath + "/auth/login" + redirectParam;
        
        DebugLogger.log("Using dynamically built redirect URI: " + redirectUri);
        String encodedRedirectUri = URLEncoder.encode(redirectUri, StandardCharsets.UTF_8.toString());

        // Start with the base logout URL
        StringBuilder logoutUrl = new StringBuilder(logoutUri);
        logoutUrl.append("?post_logout_redirect_uri=").append(encodedRedirectUri);
        
        // Add login_hint parameter if we have the user's email
        if (userEmail != null && !userEmail.isEmpty()) {
            logoutUrl.append("&login_hint=")
                    .append(URLEncoder.encode(userEmail, StandardCharsets.UTF_8.toString()));
            // Add prompt parameter to ensure user is prompted to select account
            logoutUrl.append("&prompt=select_account");
            DebugLogger.log("Added login_hint and prompt parameters for user: " + userEmail);
        }

        // Add a state parameter to help with back button handling
        String stateParam = "msallogout_" + System.currentTimeMillis();
        logoutUrl.append("&state=").append(stateParam);

        DebugLogger.log("Redirecting to Azure AD logout URL: " + logoutUrl);
        
        // Force the response to be committed
        response.flushBuffer();
        response.sendRedirect(logoutUrl.toString());
    } catch (Exception e) {
        DebugLogger.log("Error during Azure AD logout redirect: " + e.getMessage());
        // Fall back to local logout - use the appropriate URL based on logout reason
        if (isTokenExpired) {
            response.sendRedirect(request.getContextPath() + "/auth/login?expired=true");
        } else {
            response.sendRedirect(request.getContextPath() + "/auth/login?logout=true");
        }
    }
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
        // Add no-cache headers to every response
        response.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
        response.setHeader("Pragma", "no-cache");
        response.setHeader("Expires", "0");
        
        // Get the request path and log it for debugging
        String requestPath = request.getRequestURI();
        DebugLogger.log("TokenExpirationFilter processing request: " + requestPath);
        
        // Skip checking paths that should bypass token validation
        if (requestPath.startsWith(request.getContextPath() + "/logout") || 
            requestPath.startsWith(request.getContextPath() + "/auth/login") ||
            requestPath.startsWith(request.getContextPath() + "/resources")) {
            DebugLogger.log("Skipping token validation for exempt path: " + requestPath);
            filterChain.doFilter(request, response);
            return;
        }
        
        HttpSession session = request.getSession(false);
        if (session == null) {
            DebugLogger.log("No session found for request: " + requestPath);
            filterChain.doFilter(request, response);
            return;
        }
        
        UserProfile userProfile = (UserProfile) session.getAttribute("userInfo");
        if (userProfile == null) {
            DebugLogger.log("No user profile found in session for request: " + requestPath);
            filterChain.doFilter(request, response);
            return;
        }
        
        if (userProfile.getTokenExpirationTime() <= 0) {
            DebugLogger.log("Invalid token expiration time: " + userProfile.getTokenExpirationTime());
            filterChain.doFilter(request, response);
            return;
        }
        
        long tokenExpirationTime = userProfile.getTokenExpirationTime();
        long currentTime = Instant.now().getEpochSecond();
        long remainingSeconds = tokenExpirationTime - currentTime;
        
        DebugLogger.log("Request: " + requestPath + " - Token expires in: " + remainingSeconds + " seconds");
        
        // Handle token expiration
        if (currentTime >= tokenExpirationTime) {
            // Token is expired - handle this case
            DebugLogger.log("TOKEN EXPIRED for user: " + userProfile.getName() + 
                           " during request to: " + requestPath);
            
            // Double check we're not in an exempt URL
            if (!requestPath.contains("/logout") && !requestPath.contains("/login")) {
                try {
                    // Mark this as a token expiration for the logout handler
                    session.setAttribute("logout_reason", "token_expired");
                    
                    // Force a synchronous redirect to /logout
                    String logoutUrl = request.getContextPath() + "/logout";
                    DebugLogger.log("Performing redirect to: " + logoutUrl);
                    
                    // Ensure we're not buffered and the redirect happens immediately
                    response.flushBuffer();
                    response.sendRedirect(logoutUrl);
                    
                    // Log after redirect is sent
                    DebugLogger.log("Redirect to logout sent successfully");
                    return;
                } catch (Exception e) {
                    DebugLogger.log("Error during token expiration redirect: " + e.getMessage());
                    // If redirect fails, invalidate session and redirect to login
                    session.invalidate();
                    response.sendRedirect(request.getContextPath() + "/auth/login?expired=true");
                    return;
                }
            }
        } else {
            // Update the remaining time in the user profile
            userProfile.setTokenExpiresInMinutes((int)Math.ceil(remainingSeconds / 60.0));
            DebugLogger.log("Updated token expiration: " + userProfile.getTokenExpiresInMinutes() + " minutes remaining");
        }
        
        // Continue the filter chain for non-expired tokens
        filterChain.doFilter(request, response);
    }
}
