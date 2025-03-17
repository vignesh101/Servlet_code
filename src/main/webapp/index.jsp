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

package com.msal.service;

import com.microsoft.aad.msal4j.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.net.URI;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class MsalServiceTest {

    @InjectMocks
    private MsalService msalService;
    
    @Mock
    private IConfidentialClientApplication mockClientApp;
    
    @BeforeEach
    public void setup() {
        // Set the private fields using reflection
        ReflectionTestUtils.setField(msalService, "clientId", "test-client-id");
        ReflectionTestUtils.setField(msalService, "clientSecret", "test-client-secret");
        ReflectionTestUtils.setField(msalService, "tenantId", "test-tenant-id");
        ReflectionTestUtils.setField(msalService, "issuerUri", "https://test-issuer");
        ReflectionTestUtils.setField(msalService, "redirectUri", "https://test-redirect");
        ReflectionTestUtils.setField(msalService, "graphApi", "https://test-graph-api");
    }
    
    @Test
    public void testGenerateState() {
        String state = MsalService.generateState();
        assertNotNull(state);
        assertEquals(32, state.getBytes().length);
    }
    
    @Test
    public void testGetAuthorizationCodeUrl() throws Exception {
        // Mock the creation of URL
        AuthorizationRequestUrl mockAuthUrl = Mockito.mock(AuthorizationRequestUrl.class);
        when(mockAuthUrl.toString()).thenReturn("https://login.test.com/authorize");
        
        when(mockClientApp.getAuthorizationRequestUrl(any())).thenReturn(mockAuthUrl);
        
        // Use reflection to set the mocked client app
        ReflectionTestUtils.setField(msalService, "clientApp", mockClientApp);
        
        String url = msalService.getAuthorizationCodeUrl("test-state", "test-nonce");
        
        assertNotNull(url);
        assertEquals("https://login.test.com/authorize", url);
    }
    
    @Test
    public void testAcquireToken() throws Exception {
        // Create mock auth result
        IAuthenticationResult mockResult = Mockito.mock(IAuthenticationResult.class);
        when(mockResult.accessToken()).thenReturn("test-access-token");
        when(mockResult.idToken()).thenReturn("test-id-token");
        
        // Create the CompletableFuture that will return the mock result
        CompletableFuture<IAuthenticationResult> future = CompletableFuture.completedFuture(mockResult);
        
        when(mockClientApp.acquireToken(any(AuthorizationCodeParameters.class))).thenReturn(future);
        
        // Use reflection to set the mocked client app
        ReflectionTestUtils.setField(msalService, "clientApp", mockClientApp);
        
        IAuthenticationResult result = msalService.acquireToken("test-auth-code");
        
        assertNotNull(result);
        assertEquals("test-access-token", result.accessToken());
        assertEquals("test-id-token", result.idToken());
    }
    
    @Test
    public void testGetCurrentAccount() throws Exception {
        // Create a mock account
        IAccount mockAccount = Mockito.mock(IAccount.class);
        Set<IAccount> accounts = new HashSet<>();
        accounts.add(mockAccount);
        
        // Create the CompletableFuture for the accounts
        CompletableFuture<Set<IAccount>> future = CompletableFuture.completedFuture(accounts);
        
        when(mockClientApp.getAccounts()).thenReturn(future);
        
        // Use reflection to set the mocked client app
        ReflectionTestUtils.setField(msalService, "clientApp", mockClientApp);
        
        IAccount result = msalService.getCurrentAccount();
        
        assertNotNull(result);
        assertSame(mockAccount, result);
    }
}

package com.msal.filters;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.microsoft.aad.msal4j.IAuthenticationResult;
import com.msal.model.User;
import com.msal.repository.UserRepository;
import com.msal.service.MsalService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class MsalAuthenticationFilterTest {

    private MsalAuthenticationFilter filter;
    
    @Mock
    private AuthenticationManager authenticationManager;
    
    @Mock
    private MsalService msalService;
    
    @Mock
    private UserRepository userRepository;
    
    @Mock
    private IAuthenticationResult authResult;
    
    @Mock
    private CustomAuthenticationSuccessHandler successHandler;
    
    @Mock
    private CustomAuthenticationFailureHandler failureHandler;
    
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private MockHttpSession session;
    
    @BeforeEach
    public void setup() {
        // Clear security context
        SecurityContextHolder.clearContext();
        
        // Create filter
        filter = new MsalAuthenticationFilter(authenticationManager, msalService, userRepository);
        filter.setAuthenticationSuccessHandler(successHandler);
        filter.setAuthenticationFailureHandler(failureHandler);
        
        // Setup request and session
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        session = new MockHttpSession();
        request.setSession(session);
    }
    
    @Test
    public void testAttemptAuthenticationWithInvalidState() {
        // Setup request with invalid state
        request.setParameter("state", "invalid-state");
        session.setAttribute("auth_state", "original-state");
        
        // Test
        Exception exception = assertThrows(Exception.class, () -> {
            filter.attemptAuthentication(request, response);
        });
        
        assertTrue(exception.getMessage().contains("Invalid state parameter"));
    }
    
    @Test
    public void testAttemptAuthenticationWithValidCredentials() throws Exception {
        // Setup valid state
        String state = "valid-state";
        request.setParameter("state", state);
        session.setAttribute("auth_state", state);
        
        // Setup code
        request.setParameter("code", "valid-code");
        
        // Setup mock for token acquisition
        when(msalService.acquireToken(anyString())).thenReturn(authResult);
        
        // Setup mock for ID token
        String idToken = "header." + 
                new String(java.util.Base64.getEncoder().encode("{\"email\":\"test@example.com\"}".getBytes())) + 
                ".signature";
        when(authResult.idToken()).thenReturn(idToken);
        
        // Setup mock for user repository
        User mockUser = new User();
        mockUser.setId(1);
        mockUser.setName("test@example.com");
        mockUser.setRoles("admin");
        
        when(userRepository.findByName(anyString())).thenReturn(Optional.of(mockUser));
        
        // Perform the authentication
        Authentication result = filter.attemptAuthentication(request, response);
        
        // Verify results
        assertNotNull(result);
        assertTrue(result.isAuthenticated());
        assertEquals("test@example.com", result.getName());
    }
}

package com.msal.config;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest
@ContextConfiguration(classes = {SecurityConfig.class, WebConfig.class})
@Import({TestSecurityConfig.class})
public class SecurityConfigTest {

    @Autowired
    private MockMvc mockMvc;
    
    @Test
    public void testPublicEndpointsAccessible() throws Exception {
        mockMvc.perform(get("/login"))
                .andExpect(status().isOk());
                
        mockMvc.perform(get("/auth/login"))
                .andExpect(status().isOk());
                
        mockMvc.perform(get("/"))
                .andExpect(status().isOk());
    }
    
    @Test
    public void testProtectedEndpointsRedirectToLogin() throws Exception {
        mockMvc.perform(get("/home"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("http://localhost/"));
    }
    
    @Test
    @WithMockUser(roles = "USER")
    public void testAuthorizedUserCanAccessUserPages() throws Exception {
        mockMvc.perform(get("/home"))
                .andExpect(status().isOk());
    }
    
    @Test
    @WithMockUser(roles = "USER")
    public void testUserCannotAccessAdminPages() throws Exception {
        mockMvc.perform(get("/admin/home"))
                .andExpect(status().isForbidden());
    }
    
    @Test
    @WithMockUser(roles = "admin")
    public void testAdminCanAccessAdminPages() throws Exception {
        mockMvc.perform(get("/admin/home"))
                .andExpect(status().isOk());
    }
}

package com.msal.repository;

import com.msal.model.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.JdbcTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.jdbc.Sql;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@JdbcTest
@Sql({"classpath:schema.sql", "classpath:data-test.sql"})
public class UserRepositoryTest {

    @Autowired
    private JdbcTemplate jdbcTemplate;
    
    private UserRepository userRepository;
    
    @BeforeEach
    public void setup() {
        userRepository = new UserRepository(jdbcTemplate);
    }
    
    @Test
    public void testFindAll() {
        List<User> users = userRepository.findAll();
        assertFalse(users.isEmpty());
        assertEquals(3, users.size());
    }
    
    @Test
    public void testFindByNameWithExistingUser() {
        Optional<User> userOpt = userRepository.findByName("vignesh.ravishankar100@outlook.com");
        
        assertTrue(userOpt.isPresent());
        User user = userOpt.get();
        assertEquals("vignesh.ravishankar100@outlook.com", user.getName());
        assertEquals("admin", user.getRoles());
    }
    
    @Test
    public void testFindByNameWithNonExistingUser() {
        Optional<User> userOpt = userRepository.findByName("nonexistent@example.com");
        assertFalse(userOpt.isPresent());
    }
    
    @Test
    public void testFindByNameWithFallback() {
        String testEmail = "new@example.com";
        Optional<User> userOpt = userRepository.findByNameWithFallback(testEmail);
        
        assertTrue(userOpt.isPresent());
        User user = userOpt.get();
        assertEquals(testEmail, user.getName());
        assertEquals("USER", user.getRoles());
    }
}

package com.msal.controller;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import com.msal.service.MsalService;
import com.msal.repository.UserRepository;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(controllers = {HomeController.class, AdminController.class})
public class ControllerTests {

    @Autowired
    private MockMvc mockMvc;
    
    @MockBean
    private MsalService msalService;
    
    @MockBean
    private UserRepository userRepository;
    
    @Test
    @WithMockUser
    public void testHomeController() throws Exception {
        mockMvc.perform(get("/home"))
               .andExpect(status().isOk())
               .andExpect(view().name("home"));
    }
    
    @Test
    @WithMockUser(roles = "USER")
    public void testRegularUserCannotAccessAdminPage() throws Exception {
        mockMvc.perform(get("/admin/home"))
               .andExpect(status().isForbidden());
    }
    
    @Test
    @WithMockUser(roles = "admin")
    public void testAdminCanAccessAdminPage() throws Exception {
        mockMvc.perform(get("/admin/home"))
               .andExpect(status().isOk())
               .andExpect(view().name("admin_home"));
    }
}

package com.msal;

import com.msal.config.SecurityConfig;
import com.msal.config.WebConfig;
import com.msal.model.User;
import com.msal.repository.UserRepository;
import com.msal.service.MsalService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.Optional;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(classes = {SecurityConfig.class, WebConfig.class})
@AutoConfigureMockMvc
public class AuthenticationFlowIntegrationTest {

    @Autowired
    private MockMvc mockMvc;
    
    @MockBean
    private MsalService msalService;
    
    @MockBean
    private UserRepository userRepository;
    
    private MockHttpSession session;
    
    @BeforeEach
    public void setup() {
        session = new MockHttpSession();
        
        // Setup user repository mock
        User mockUser = new User();
        mockUser.setId(1);
        mockUser.setName("test@example.com");
        mockUser.setRoles("admin");
        when(userRepository.findByName(anyString())).thenReturn(Optional.of(mockUser));
    }
    
    @Test
    public void testAuthenticationFlow() throws Exception {
        // 1. User accesses protected resource and gets redirected to login
        MvcResult result = mockMvc.perform(get("/home").session(session))
                .andExpect(status().is3xxRedirection())
                .andReturn();
        
        // 2. User logs in through Microsoft (we'll skip the actual external auth)
        // Instead, we'll simulate a successful return from Microsoft
        
        // First, set up the session as if state was previously stored
        String state = "test-state";
        session.setAttribute("auth_state", state);
        
        // Mock the authorization URL
        when(msalService.getAuthorizationCodeUrl(anyString(), anyString()))
                .thenReturn("https://login.microsoftonline.com/test");
        
        // Simulate clicking "Sign in with Microsoft"
        mockMvc.perform(get("/auth/microsoft").session(session))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("https://login.microsoftonline.com/test"));
        
        // 3. Test the logout process
        mockMvc.perform(get("/logout").session(session))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/auth/login?logout=true"));
    }
}

package com.msal.model;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collection;

import static org.junit.jupiter.api.Assertions.*;

public class UserPrincipalTest {

    @Test
    public void testGetAuthoritiesWithRoles() {
        // Create a user with roles
        User user = new User();
        user.setId(1);
        user.setName("test@example.com");
        user.setRoles("admin,user");
        
        // Create principal
        UserPrincipal principal = new UserPrincipal(user);
        
        // Test authorities
        Collection<? extends GrantedAuthority> authorities = principal.getAuthorities();
        
        assertNotNull(authorities);
        assertEquals(2, authorities.size());
        assertTrue(authorities.contains(new SimpleGrantedAuthority("ROLE_admin")));
        assertTrue(authorities.contains(new SimpleGrantedAuthority("ROLE_user")));
    }
    
    @Test
    public void testGetAuthoritiesWithNoRoles() {
        // Create a user with no roles
        User user = new User();
        user.setId(1);
        user.setName("test@example.com");
        user.setRoles("");
        
        // Create principal
        UserPrincipal principal = new UserPrincipal(user);
        
        // Test authorities
        Collection<? extends GrantedAuthority> authorities = principal.getAuthorities();
        
        assertNotNull(authorities);
        assertEquals(1, authorities.size());
        assertTrue(authorities.contains(new SimpleGrantedAuthority("ROLE_USER")));
    }
    
    @Test
    public void testUserDetails() {
        // Create a user
        User user = new User();
        user.setId(1);
        user.setName("test@example.com");
        user.setRoles("admin");
        
        // Create principal
        UserPrincipal principal = new UserPrincipal(user);
        
        // Test UserDetails implementation
        assertEquals("test@example.com", principal.getUsername());
        assertNull(principal.getPassword());
        assertTrue(principal.isAccountNonExpired());
        assertTrue(principal.isAccountNonLocked());
        assertTrue(principal.isCredentialsNonExpired());
        assertTrue(principal.isEnabled());
        assertEquals(user, principal.getUser());
        assertEquals("test@example.com", principal.getName());
    }
}
