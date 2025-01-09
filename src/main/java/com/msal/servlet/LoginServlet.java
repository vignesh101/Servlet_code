package com.msal.servlet;

import com.msal.auth.MsalClientProvider;
import com.msal.config.AuthConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import java.io.IOException;

@WebServlet("/auth/login")
public class LoginServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        try {
            HttpSession session = request.getSession(true);
            String state = AuthConfig.generateState();
            String nonce = AuthConfig.generatePkce();

            session.setAttribute("state", state);
            session.setAttribute("nonce", nonce);

            String authUrl = MsalClientProvider.getAuthorizationCodeUrl(state, nonce);
            response.sendRedirect(authUrl);
        } catch (Exception e) {
            throw new ServletException("Failed to initiate login", e);
        }
    }
}
