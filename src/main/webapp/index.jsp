// Add this to the SecurityConfig.java class

@Bean
public TokenExpirationFilter tokenExpirationFilter() {
    return new TokenExpirationFilter();
}

// Then modify the configure(HttpSecurity http) method to add our filter

@Override
protected void configure(HttpSecurity http) throws Exception {
    http
            // Configure authorization for requests
            .authorizeRequests()
            .antMatchers("/login/oauth2/code/**").permitAll()
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
            .expiredUrl("/auth/login?expired=true")
            .maxSessionsPreventsLogin(false)
            .and()
            .sessionFixation().migrateSession()
            .invalidSessionUrl("/auth/login?invalid=true")

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

            // Add filters
            .and()
            .addFilterBefore(msalAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
            .addFilterAfter(tokenExpirationFilter(), SecurityContextPersistenceFilter.class) // Add our token expiration filter

            //Access denied
            .exceptionHandling()
            .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/"))
            .accessDeniedPage("/access-denied")

            .and()
            // Disable CSRF for development (enable in production)
            .csrf().disable();
}

// Modified code for processSuccessfulAuth method in MsalAuthenticationFilter.java

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

        // Create and store user profile in session
        UserProfile userProfile = new UserProfile();
        userProfile.setName(email);
        
        // Extract token expiration time and store in session
        if (tokenJson.has("exp")) {
            long expirationTimestamp = tokenJson.get("exp").asLong();
            long currentTimestamp = java.time.Instant.now().getEpochSecond();
            long expiresInSeconds = expirationTimestamp - currentTimestamp;
            int expiresInMinutes = (int) Math.ceil(expiresInSeconds / 60.0);
            
            // Store both the absolute expiration time and the relative time in minutes
            userProfile.setTokenExpirationTime(expirationTimestamp);
            userProfile.setTokenExpiresInMinutes(expiresInMinutes);
            
            // Also set the session timeout to match the token expiration (in seconds)
            // Add a small buffer (30 seconds) to ensure our filter handles the expiration first
            int sessionTimeoutSeconds = (int) Math.max(expiresInSeconds - 30, 60); // Minimum 1 minute
            session.setMaxInactiveInterval(sessionTimeoutSeconds);
            
            DebugLogger.log("Token expires in " + expiresInMinutes + " minutes. Session timeout set to " + sessionTimeoutSeconds + " seconds");
        }
        
        session.setAttribute("userInfo", userProfile);

        // Find or create user in repository
        Optional<User> userOpt = userRepository.findByName(email);

        if (!userOpt.isPresent()) {
            throw new AuthenticationException("User not found") {
                private static final long serialVersionUID = 1L;
            };
        }

        User user = userOpt.get();

        DebugLogger.log("User authenticated with roles: " + user.getRoles());

        UserPrincipal userPrincipal = new UserPrincipal(user);

        // Create authentication token with user roles
        return new UsernamePasswordAuthenticationToken(
                userPrincipal,
                null, // No credentials needed since Azure AD handles authentication
                userPrincipal.getAuthorities()
        );
    }

    throw new AuthenticationException("Invalid ID token format") {
        private static final long serialVersionUID = 1L;
    };
}


// 1. Create a new TokenExpirationFilter.java class
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
        
        HttpSession session = request.getSession(false);
        
        if (session != null) {
            // Check if there's a user profile in the session
            UserProfile userProfile = (UserProfile) session.getAttribute("userInfo");
            
            if (userProfile != null && userProfile.getTokenExpirationTime() > 0) {
                // Get the token expiration time
                long tokenExpirationTime = userProfile.getTokenExpirationTime();
                long currentTime = Instant.now().getEpochSecond();
                
                // Check if the token has expired
                if (currentTime >= tokenExpirationTime) {
                    DebugLogger.log("Token has expired. Invalidating session.");
                    
                    // Invalidate the session
                    session.invalidate();
                    
                    // Redirect to login page with expired=true parameter
                    response.sendRedirect(request.getContextPath() + "/auth/login?expired=true");
                    return;
                }
                
                // Optionally: Update remaining time for display purposes
                long remainingSeconds = tokenExpirationTime - currentTime;
                userProfile.setTokenExpiresInMinutes((int)Math.ceil(remainingSeconds / 60.0));
            }
        }
        
        // Continue with the filter chain
        filterChain.doFilter(request, response);
    }
}
