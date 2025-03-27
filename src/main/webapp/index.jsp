package com.msal.filters;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.microsoft.aad.msal4j.IAuthenticationResult;
import com.msal.log.DebugLogger;
import com.msal.model.User;
import com.msal.model.UserPrincipal;
import com.msal.model.UserProfile;
import com.msal.repository.UserRepository;
import com.msal.service.MsalService;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.Optional;

public class MsalAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private final MsalService msalService;
    private final UserRepository userRepository;

    public MsalAuthenticationFilter(AuthenticationManager authenticationManager,
                                    MsalService msalService,
                                    UserRepository userRepository) {
        super(new AntPathRequestMatcher("/login/oauth2/code/**"));
        setAuthenticationManager(authenticationManager);
        this.msalService = msalService;
        this.userRepository = userRepository;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {

        String returnedState = request.getParameter("state");
        String originalState = (String) request.getSession().getAttribute("auth_state");

        DebugLogger.log("Returned state: " + returnedState);
        DebugLogger.log("Original state from session: " + originalState);

        if (returnedState == null || !returnedState.equals(originalState)) {
            DebugLogger.log("State parameter mismatch! Returned: " + returnedState + ", Original: " + originalState);
            throw new AuthenticationException("Invalid state parameter") {
                private static final long serialVersionUID = 1L;
            };
        }

        String error = request.getParameter("error");
        String errorDescription = request.getParameter("error_description");
        if (error != null) {
            throw new AuthenticationException("Azure AD returned an error: " + error + " - " + errorDescription) {
                private static final long serialVersionUID = 1L;
            };
        }

        String code = request.getParameter("code");
        if (code == null) {
            throw new AuthenticationException("Authorization code not found") {
                private static final long serialVersionUID = 1L;
            };
        }

        try {
            IAuthenticationResult result = msalService.acquireToken(code);

            String returnedNonce = extractNonceFromToken(result.idToken());
            String originalNonce = (String) request.getSession().getAttribute("auth_nonce");

            Authentication auth = processSuccessfulAuth(result, request.getSession());

            SecurityContextHolder.getContext().setAuthentication(auth);

            return auth;
        } catch (Exception e) {
            DebugLogger.log("Authentication failed: " + e.getMessage());
            throw new AuthenticationException("Authentication failed: " + e.getMessage()) {
                private static final long serialVersionUID = 1L;
            };
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                            FilterChain chain, Authentication authResult)
            throws IOException, ServletException {
        super.successfulAuthentication(request, response, chain, authResult);

        request.getSession().removeAttribute("auth_state");
        request.getSession().removeAttribute("auth_nonce");
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                              AuthenticationException failed)
            throws IOException, ServletException {

        request.getSession().removeAttribute("auth_state");
        request.getSession().removeAttribute("auth_nonce");

        super.unsuccessfulAuthentication(request, response, failed);
    }

    private String extractNonceFromToken(String idToken) throws Exception {
        if (idToken == null) {
            return null;
        }

        String[] parts = idToken.split("\\.");
        if (parts.length != 3) {
            throw new AuthenticationException("Invalid ID token format") {};
        }

        byte[] decodedBytes = java.util.Base64.getUrlDecoder().decode(parts[1]);
        String decodedPayload = new String(decodedBytes, java.nio.charset.StandardCharsets.UTF_8);

        ObjectMapper mapper = new ObjectMapper();
        JsonNode tokenJson = mapper.readTree(decodedPayload);

        return tokenJson.has("nonce") ? tokenJson.get("nonce").asText() : null;
    }

    private Authentication processSuccessfulAuth(IAuthenticationResult result, HttpSession session) throws Exception {
        String idToken = result.idToken();
        String[] parts = idToken.split("\\.");

        ObjectMapper mapper = new ObjectMapper();

        if (parts.length > 1) {
            byte[] decodedBytes = java.util.Base64.getUrlDecoder().decode(parts[1]);
            String decodedPayload = new String(decodedBytes, java.nio.charset.StandardCharsets.UTF_8);

            DebugLogger.log("ID Token payload: " + decodedPayload);

            JsonNode tokenJson = mapper.readTree(decodedPayload);

            String email = extractEmailFromToken(tokenJson);

            if (email == null) {
                throw new AuthenticationException("Could not extract email from token") {
                    private static final long serialVersionUID = 1L;
                };
            }

            DebugLogger.log("Authenticated email: " + email);

            UserProfile userProfile = new UserProfile();
            userProfile.setName(email);
            session.setAttribute("userInfo", userProfile);



            Optional<User> userOpt = userRepository.findByName(email);

            if (!userOpt.isPresent()) {
                throw new AuthenticationException("User not found") {
                    private static final long serialVersionUID = 1L;
                };
            }

            User user = userOpt.get();

//            if (tokenJson.has("exp")) {
//
//                long expirationTimestamp = tokenJson.get("exp").asLong();
//                long currentTimestamp = java.time.Instant.now().getEpochSecond();
//                long expiresInSeconds = expirationTimestamp - currentTimestamp;
//
//                session.setAttribute("expirationTimestamp", expirationTimestamp);
//
//                int sessionTimeoutSeconds = (int) Math.max(expiresInSeconds - 30, 60);
//                session.setMaxInactiveInterval(sessionTimeoutSeconds);
//
//            }
//            else{

                long currentTimestamp = java.time.Instant.now().getEpochSecond();
                long expiresInSeconds = currentTimestamp + (1*60);

                int sessionTimeoutSeconds = 55;

                session.setAttribute("expirationTimestamp", expiresInSeconds);

                session.setMaxInactiveInterval(sessionTimeoutSeconds);

//            }

            DebugLogger.log("User authenticated with roles: " + user.getRoles());

            UserPrincipal userPrincipal = new UserPrincipal(user);

            return new UsernamePasswordAuthenticationToken(
                    userPrincipal,
                    null,
                    userPrincipal.getAuthorities()
            );
        }

        throw new AuthenticationException("Invalid ID token format") {
            private static final long serialVersionUID = 1L;
        };
    }

    private String extractEmailFromToken(JsonNode tokenJson) {
        if (tokenJson.has("email")) {
            return tokenJson.get("email").asText();
        } else if (tokenJson.has("preferred_username")) {
            return tokenJson.get("preferred_username").asText();
        } else if (tokenJson.has("upn")) {
            return tokenJson.get("upn").asText();
        }
        return null;
    }
}



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



package com.msal.config;

import com.msal.filters.*;
import com.msal.log.DebugLogger;
import com.msal.repository.UserRepository;
import com.msal.service.MsalService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;

import javax.servlet.Filter;
import java.util.List;

@EnableWebSecurity
@ComponentScan(basePackages = {"com.msal.filters", "com.msal.service", "com.msal.repository", "com.msal.controller"})
@Configuration
public class SecurityConfig {

    @Autowired
    private CustomAuthenticationSuccessHandler successHandler;

    @Autowired
    private CustomAuthenticationFailureHandler failureHandler;

    @Autowired
    private MsalService msalService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private CustomLogoutHandler customLogoutHandler;


    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    @Bean
    public TokenExpirationFilter tokenExpirationFilter(){
        return new TokenExpirationFilter(customLogoutHandler);
    }

    @Bean
    public CacheControlFilter cacheControlFilter(){
        return new CacheControlFilter();
    }

    @Bean
    public MsalAuthenticationFilter msalAuthenticationFilter(AuthenticationManager authenticationManager) throws Exception {
        MsalAuthenticationFilter filter = new MsalAuthenticationFilter(
                authenticationManager,
                msalService,
                userRepository
        );
        filter.setAuthenticationSuccessHandler(successHandler);
        filter.setAuthenticationFailureHandler(failureHandler);
        return filter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, AuthenticationManager authenticationManager) throws Exception {
        http
                // Configure authorization for requests
                .authorizeRequests()
                .antMatchers(HttpMethod.POST,"/login/oauth2/code/**").permitAll()
                .antMatchers("/h2-console/**").permitAll()
                .antMatchers("/", "/index", "/auth/**", "/login/**", "/resources/**", "/debug/**").permitAll()

                //Role based access
                .antMatchers("/admin/**").hasRole("admin")
                .anyRequest().authenticated()

                // Configure session management
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                .maximumSessions(1)
                .maxSessionsPreventsLogin(false)
                .and()
                .sessionFixation().newSession()

                // Configure security context
                .and()
                .securityContext()
                .securityContextRepository(new HttpSessionSecurityContextRepository())

                // Configure logout
                .and()
                .logout()
                .logoutUrl("/logout")
                .logoutSuccessHandler(customLogoutHandler)
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID")
                .permitAll()

                // Add MSAL filter
                .and()
                .addFilterBefore(cacheControlFilter(), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(msalAuthenticationFilter(authenticationManager), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(tokenExpirationFilter(), SecurityContextPersistenceFilter.class)

                //Access denied
                .exceptionHandling()
                .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/"))
                .accessDeniedPage("/access-denied")

                .and()
                .headers()
                .cacheControl()
                .and()
                .httpStrictTransportSecurity()
                .and()
                .frameOptions()
                .deny()

                .and()
                // Disable CSRF for development
                .csrf().disable();

        return http.build();
    }
}


package com.msal.filters;

import com.msal.log.DebugLogger;
import com.msal.model.UserProfile;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.web.servlet.oauth2.resourceserver.OAuth2ResourceServerSecurityMarker;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.time.Instant;

public class TokenExpirationFilter extends OncePerRequestFilter {


    private final CustomLogoutHandler customLogoutHandler;

    @Autowired
    public TokenExpirationFilter(CustomLogoutHandler customLogoutHandler){
        this.customLogoutHandler = customLogoutHandler;
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {


        String requestPath = request.getRequestURI();
        DebugLogger.log("TokenExpirationFilter processing request: " + requestPath);

        HttpSession session = request.getSession(false);

        if (session != null) {


            Object expirationTimestamp = session.getAttribute("expirationTimestamp");

            if (expirationTimestamp instanceof Long) {

                long tokenExpirationTime = (Long) expirationTimestamp;
                long currentTime = Instant.now().getEpochSecond();

                if (currentTime >= tokenExpirationTime) {
                    DebugLogger.log("Token has expired. Invalidating session.");

                    try {

                        session.setAttribute("token_expired", true);

                        customLogoutHandler.onLogoutSuccess(
                                request,
                                response,
                                SecurityContextHolder.getContext().getAuthentication()
                        );
                        return;
                    } catch (Exception e) {
                        DebugLogger.log("Error during automatic logout: " + e.getMessage());
                        session.invalidate();
                        response.sendRedirect(request.getContextPath() + "/auth/login?expired=true");
                        return;
                    }
                }
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

        // Add no-cache headers
        response.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
        response.setHeader("Pragma", "no-cache");
        response.setHeader("Expires", "0");

        boolean tokenExpired = false;
        HttpSession session = request.getSession(false);

        if (session != null) {
            Object expiredObj = session.getAttribute("token_expired");
            if (expiredObj instanceof Boolean) {
                tokenExpired = (Boolean) expiredObj;
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

        try {
            String redirectUri = postLogoutRedirectUri;
            if (tokenExpired) {
                redirectUri += (redirectUri.contains("?") ? "&" : "?") + "expired=true";
            }

            String encodedRedirectUri = URLEncoder.encode(redirectUri, StandardCharsets.UTF_8.toString());

            String logoutUrl = logoutUri + "?post_logout_redirect_uri=" + encodedRedirectUri;

            DebugLogger.log("Redirecting to logout URL: " + logoutUrl);
            response.sendRedirect(logoutUrl);
        } catch (Exception e) {
            DebugLogger.log("Error during logout redirect: " + e.getMessage());
            String redirectUrl = request.getContextPath() + "/auth/login?";
            redirectUrl += tokenExpired ? "expired=true" : "logout=true";
            response.sendRedirect(redirectUrl);
        }
    }
}

package com.msal.controller;

import com.microsoft.aad.msal4j.*;
import com.msal.log.DebugLogger;
import com.msal.service.MsalService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.Set;

@Controller
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private MsalService msalService;

    @GetMapping("/microsoft")
    public String microsoftLogin(HttpServletRequest request) throws Exception {

        HttpSession httpSession = request.getSession(false);

        if(httpSession != null){
            httpSession.invalidate();
        }

        HttpSession session = request.getSession(true);

        String state = MsalService.generateState();
        String nonce = MsalService.generatePkce();

        session.setAttribute("auth_state", state);
        session.setAttribute("auth_nonce", nonce);

        String authUrl = msalService.getAuthorizationCodeUrl(state, nonce);
        return "redirect:" + authUrl;
    }

    @GetMapping("/login")
    public String login(@RequestParam(required = false) String error,
                        @RequestParam(required = false) String logout,
                        HttpSession session,
                        Model model) {
        if (error != null) {
            String authError = (String) session.getAttribute("authError");
            DebugLogger.log("auth error from login: "+authError);
            model.addAttribute("error", authError);
        }
        if (logout != null) {
            model.addAttribute("message", "You have been logged out.");
        }
        return "login";
    }

}
