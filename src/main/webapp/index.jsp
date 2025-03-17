package com.msal.filters;

import com.microsoft.aad.msal4j.IAccount;
import com.microsoft.aad.msal4j.IConfidentialClientApplication;
import com.msal.log.DebugLogger;
import com.msal.service.MsalService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.Set;

@Component
public class CustomLogoutSuccessHandler extends SimpleUrlLogoutSuccessHandler {

    @Autowired
    private MsalService msalService;

    public CustomLogoutSuccessHandler() {
        // Set default target URL for redirect after logout
        setDefaultTargetUrl("/auth/login?logout=true");
    }

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response,
                              Authentication authentication) throws IOException, ServletException {
        HttpSession session = request.getSession(false);
        
        DebugLogger.log("Logout initiated");
        
        // Clean up MSAL resources
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

        // Clear custom session attributes if session exists
        if (session != null) {
            session.removeAttribute("userInfo");
            session.removeAttribute("auth_state");
            session.removeAttribute("auth_nonce");
        }

        // Call the parent method to handle the redirect
        super.onLogoutSuccess(request, response, authentication);
    }
}
