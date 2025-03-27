String returnedNonce = extractNonceFromToken(request); // Implement this
    String originalNonce = (String) request.getSession().getAttribute("auth_nonce");
    if (!returnedNonce.equals(originalNonce)) {
        throw new AuthenticationException("Invalid nonce parameter") {};
    }



private String extractNonceFromToken(String idToken) throws Exception {
        if (idToken == null) {
            return null;
        }
        // ID token is a JWT with three parts: header.payload.signature
        String[] parts = idToken.split("\\.");
        if (parts.length != 3) {
            throw new AuthenticationException("Invalid ID token format") {};
        }

        // Decode the payload (second part)
        byte[] decodedBytes = java.util.Base64.getUrlDecoder().decode(parts[1]);
        String decodedPayload = new String(decodedBytes, java.nio.charset.StandardCharsets.UTF_8);

        // Parse JSON payload
        ObjectMapper mapper = new ObjectMapper();
        JsonNode tokenJson = mapper.readTree(decodedPayload);

        // Extract nonce
        return tokenJson.has("nonce") ? tokenJson.get("nonce").asText() : null;
    }




.and()
.headers()
.cacheControl()
.and()
.httpStrictTransportSecurity()
.and()
.frameOptions()
.deny()


response.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
        response.setHeader("Pragma", "no-cache");
        response.setDateHeader("Expires", 0);


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
