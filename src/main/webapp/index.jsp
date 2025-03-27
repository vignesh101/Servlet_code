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
    private final ObjectMapper mapper = new ObjectMapper(); // Reuse single instance

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
            throw new AuthenticationException("Invalid state parameter") {};
        }

        String error = request.getParameter("error");
        String errorDescription = request.getParameter("error_description");
        if (error != null) {
            throw new AuthenticationException("Azure AD returned an error: " + error + " - " + errorDescription) {};
        }

        String code = request.getParameter("code");
        if (code == null) {
            throw new AuthenticationException("Authorization code not found") {};
        }

        try {
            IAuthenticationResult result = msalService.acquireToken(code);
            JsonNode tokenJson = parseIdToken(result.idToken());

            // Validate nonce
            String returnedNonce = tokenJson.has("nonce") ? tokenJson.get("nonce").asText() : null;
            String originalNonce = (String) request.getSession().getAttribute("auth_nonce");
            if (returnedNonce == null || !returnedNonce.equals(originalNonce)) {
                DebugLogger.log("Nonce mismatch: returned=" + returnedNonce + ", original=" + originalNonce);
                throw new AuthenticationException("Invalid nonce parameter") {};
            }

            Authentication auth = processSuccessfulAuth(result, tokenJson, request.getSession());
            SecurityContextHolder.getContext().setAuthentication(auth);
            return auth;
        } catch (Exception e) {
            DebugLogger.log("Authentication failed: " + e.getMessage());
            throw new AuthenticationException("Authentication failed: " + e.getMessage()) {};
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

    private JsonNode parseIdToken(String idToken) throws AuthenticationException {
        if (idToken == null) {
            throw new AuthenticationException("ID token is null") {};
        }

        String[] parts = idToken.split("\\.");
        if (parts.length != 3) {
            throw new AuthenticationException("Invalid ID token format") {};
        }

        try {
            byte[] decodedBytes = java.util.Base64.getUrlDecoder().decode(parts[1]);
            String decodedPayload = new String(decodedBytes, java.nio.charset.StandardCharsets.UTF_8);
            DebugLogger.log("ID Token payload: " + decodedPayload);
            return mapper.readTree(decodedPayload);
        } catch (Exception e) {
            DebugLogger.log("Failed to parse ID token: " + e.getMessage());
            throw new AuthenticationException("Failed to parse ID token: " + e.getMessage()) {};
        }
    }

    private Authentication processSuccessfulAuth(IAuthenticationResult result, JsonNode tokenJson, HttpSession session)
            throws AuthenticationException {
        String email = extractEmailFromToken(tokenJson);
        if (email == null) {
            throw new AuthenticationException("Could not extract email from token") {};
        }

        DebugLogger.log("Authenticated email: " + email);

        UserProfile userProfile = new UserProfile();
        userProfile.setName(email);
        session.setAttribute("userInfo", userProfile);

        Optional<User> userOpt = userRepository.findByName(email);
        if (!userOpt.isPresent()) {
            throw new AuthenticationException("User not found") {};
        }

        User user = userOpt.get();

        if (tokenJson.has("exp")) {
            long expirationTimestamp = tokenJson.get("exp").asLong();
            long currentTimestamp = java.time.Instant.now().getEpochSecond();
            long expiresInSeconds = expirationTimestamp - currentTimestamp;
            session.setAttribute("expirationTimestamp", expirationTimestamp);
            // Optionally set session timeout slightly longer
            // session.setMaxInactiveInterval((int) expiresInSeconds + 5);
        } else {
            long currentTimestamp = java.time.Instant.now().getEpochSecond();
            long expiresInSeconds = currentTimestamp + (1 * 60);
            session.setAttribute("expirationTimestamp", expiresInSeconds);
        }

        DebugLogger.log("User authenticated with roles: " + user.getRoles());

        UserPrincipal userPrincipal = new UserPrincipal(user);
        return new UsernamePasswordAuthenticationToken(
                userPrincipal,
                null,
                userPrincipal.getAuthorities()
        );
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
