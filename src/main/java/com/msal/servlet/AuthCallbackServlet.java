package com.msal.servlet;

import com.microsoft.aad.msal4j.IAuthenticationResult;
import com.msal.auth.MsalClientProvider;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import java.io.IOException;

@WebServlet("/login/oauth2/code/")
public class AuthCallbackServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        try {
            HttpSession session = request.getSession(false);
            if (session == null) {
                throw new ServletException("No session found");
            }

            // Validate state
            String expectedState = (String) session.getAttribute("state");
            String actualState = request.getParameter("state");
            if (!expectedState.equals(actualState)) {
                throw new ServletException("Invalid state parameter");
            }

            String authCode = request.getParameter("code");
            IAuthenticationResult result = MsalClientProvider.acquireToken(authCode);

            // Store tokens
            session.setAttribute("accessToken", result.accessToken());
            session.setAttribute("idToken", result.idToken());

            // Clear state and nonce
            session.removeAttribute("state");
            session.removeAttribute("nonce");

            response.sendRedirect(request.getContextPath() + "/secure/home");
        } catch (Exception e) {
            throw new ServletException("Authentication failed", e);
        }
    }
}
