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

        HttpSession session = request.getSession();
//
//        if (session != null) {


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

        filterChain.doFilter(request, response);
    }
}
