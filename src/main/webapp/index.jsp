# Step-by-Step Overview of Each Class

Here's a breakdown of each class in the Spring MSAL Demo application and what it does:

## Configuration Classes

### 1. AppConfig.java
- **Purpose**: Main application configuration and servlet initialization
- **Steps**:
  1. Defines root configuration classes (SecurityConfig, DatabaseConfig)
  2. Sets up servlet mappings
  3. Configures Spring Security filter chain
  4. Registers session listeners
  5. Sets cookie-based session tracking

### 2. SecurityConfig.java
- **Purpose**: Configures Spring Security and authentication
- **Steps**:
  1. Sets up authentication manager
  2. Configures the MSAL authentication filter
  3. Defines URL access patterns (which URLs need authentication)
  4. Configures session management policies
  5. Sets up logout handling

### 3. WebConfig.java
- **Purpose**: Configures Spring MVC components
- **Steps**:
  1. Loads properties from application.properties
  2. Sets up view resolver for JSP pages
  3. Configures resource handlers for static content
  4. Enables default servlet handling

### 4. DatabaseConfig.java
- **Purpose**: Sets up database connection and initialization
- **Steps**:
  1. Configures H2 database connection
  2. Creates the database directory if it doesn't exist
  3. Sets up JDBC template
  4. Initializes database with schema and sample data

### 5. SecurityWebApplicationInitializer.java
- **Purpose**: Registers Spring Security filters
- **Steps**:
  1. Extends AbstractSecurityWebApplicationInitializer to register Spring Security in servlet context

## Filters and Authentication Handlers

### 6. MsalAuthenticationFilter.java
- **Purpose**: Processes Microsoft authentication responses
- **Steps**:
  1. Intercepts requests to /login/oauth2/code/
  2. Validates the state parameter to prevent CSRF
  3. Exchanges authorization code for tokens
  4. Extracts user information from ID token
  5. Looks up user in database to determine roles
  6. Creates Spring Security authentication object

### 7. TokenExpirationFilter.java
- **Purpose**: Checks token expiration and forces re-login when needed
- **Steps**:
  1. Runs on each request
  2. Checks if token expiration time is in session
  3. Compares current time to expiration time
  4. Redirects to login if token is expired

### 8. CustomAuthenticationSuccessHandler.java
- **Purpose**: Handles successful authentication routing
- **Steps**:
  1. Sets default target URL to /home
  2. Redirects user after successful authentication

### 9. CustomAuthenticationFailureHandler.java
- **Purpose**: Processes authentication failures
- **Steps**:
  1. Captures authentication exceptions
  2. Stores error messages in session
  3. Redirects to debug page

### 10. CustomLogoutHandler.java
- **Purpose**: Manages logout process
- **Steps**:
  1. Removes accounts from MSAL token cache
  2. Clears cookies
  3. Invalidates session
  4. Redirects to Microsoft logout endpoint

## Services

### 11. MsalService.java
- **Purpose**: Core service for Microsoft authentication
- **Steps**:
  1. Creates and manages MSAL client
  2. Generates authorization URL for login
  3. Exchanges authorization code for tokens
  4. Manages token cache
  5. Gets user information from Microsoft Graph

### 12. MsalUserDetailsService.java
- **Purpose**: Bridges Microsoft authentication with Spring Security
- **Steps**:
  1. Creates Spring Security UserDetails from Microsoft-authenticated users
  2. Assigns default roles

## Models

### 13. User.java
- **Purpose**: Represents user data from database
- **Steps**:
  1. Stores user attributes (id, name, salary, roles)
  2. Provides method to convert role string to Role objects

### 14. UserPrincipal.java
- **Purpose**: Adapts User to Spring Security's UserDetails
- **Steps**:
  1. Implements UserDetails interface for Spring Security
  2. Converts user roles to Spring GrantedAuthority objects
  3. Provides authentication-related methods

### 15. UserProfile.java
- **Purpose**: Stores user profile information in session
- **Steps**:
  1. Holds user attributes from Microsoft
  2. Tracks token expiration information

## Repository

### 16. UserRepository.java
- **Purpose**: Data access for user information
- **Steps**:
  1. Queries database for user data
  2. Maps database rows to User objects
  3. Provides fallback user creation if not found

## Controllers

### 17. AuthController.java
- **Purpose**: Handles authentication requests
- **Steps**:
  1. Initiates Microsoft authentication
  2. Generates state and nonce for security
  3. Manages login form display with error messages

### 18. HomeController.java
- **Purpose**: Manages main application views
- **Steps**:
  1. Shows index page
  2. Renders home page with user information
  3. Provides debug endpoints for logs and cache

### 19. AdminController.java
- **Purpose**: Handles admin-only pages
- **Steps**:
  1. Shows admin dashboard
  2. Restricted to users with admin role

### 20. AccessDeniedController.java
- **Purpose**: Handles unauthorized access attempts
- **Steps**:
  1. Shows access denied page
  2. Logs access denial

### 21. LoginController.java
- **Purpose**: Manages login page display
- **Steps**:
  1. Shows login form
  2. Handles various login states (errors, logout, expired session)

## Utilities

### 22. DebugLogger.java
- **Purpose**: Custom logging utility
- **Steps**:
  1. Initializes log file
  2. Writes timestamped log messages
  3. Provides error logging with stack traces

## Listeners

### 23. SessionTimeoutListener.java
- **Purpose**: Manages session timeout
- **Steps**:
  1. Sets timeout duration when sessions are created
  2. Logs session creation and destruction

Each class plays a specific role in the authentication flow, from handling Microsoft OAuth callbacks to managing session state and ensuring proper authorization for protected resources.


# How the Spring MSAL Demo Application Works

Let me walk through how this code works step-by-step, following the flow of a typical user login and interaction with the application.

## Authentication Flow

### 1. Initial Request
When a user first accesses the application:
- `HomeController` serves the initial page
- If not authenticated, the user sees the login page (`login.jsp`)
- The login page displays a "Sign in with Microsoft" button

### 2. Microsoft Authentication Initiation
When the user clicks "Sign in with Microsoft":
- Browser sends request to `/auth/microsoft` endpoint
- `AuthController.microsoftLogin()` method:
  1. Generates a random state and nonce for security
  2. Stores these values in the session
  3. Calls `msalService.getAuthorizationCodeUrl()` to build the Microsoft login URL
  4. Redirects the user to Microsoft's login page

### 3. Microsoft Authentication
- User logs in on Microsoft's page
- Microsoft validates credentials
- Microsoft redirects back to the application's callback URL with an authorization code

### 4. Authorization Code Processing
- The redirect hits `/login/oauth2/code/` which is intercepted by `MsalAuthenticationFilter`
- The filter:
  1. Verifies the state parameter matches what was stored (prevents CSRF)
  2. Extracts the authorization code
  3. Calls `msalService.acquireToken()` to exchange the code for tokens
  4. Extracts user information from the ID token
  5. Looks up the user in the database through `UserRepository`
  6. Creates a `UserPrincipal` with appropriate roles
  7. Stores user profile in session
  8. Sets Spring Security context with the authentication

### 5. Redirection After Login
- `CustomAuthenticationSuccessHandler` redirects to the home page
- `HomeController.home()` serves the home page with user information
- The page shows different options based on user roles

## Session and Token Management

### 1. Token Expiration Tracking
- `TokenExpirationFilter` runs on each request to check if the token is expired
- It compares the current time with the token expiration time stored in session
- If expired, it invalidates the session and redirects to login

### 2. Session Management
- `SessionTimeoutListener` sets session timeout when a new session is created
- The timeout is typically aligned with token expiration
- Session fixation protection is enabled in `SecurityConfig`

## Authorization and Access Control

### 1. URL Protection
- `SecurityConfig.configure(HttpSecurity http)` defines which URLs require authentication
- URLs like `/admin/**` require specific roles (ROLE_admin)
- Public URLs like `/auth/**` and `/login/**` are accessible without login

### 2. Role-Based Access
- When a user tries to access a protected URL:
  1. Spring Security checks if the user is authenticated
  2. If authenticated, it checks if the user has the required role
  3. If not, `AccessDeniedController` shows the access denied page

### 3. Database Role Lookup
- `UserRepository.findByName()` looks up user by email in the database
- The `User` object contains roles as a comma-separated string
- `UserPrincipal.getAuthorities()` converts these roles to Spring Security authorities

## Logout Process

When a user logs out:
1. Browser sends request to `/logout`
2. `CustomLogoutHandler` executes:
   - Clears MSAL token cache
   - Removes cookies
   - Invalidates the session
   - Redirects to Microsoft's logout endpoint
3. After Microsoft logout, user is redirected back to the application's login page

## Data Flow

### 1. Database Initialization
- When the application starts, `DatabaseConfig` initializes the H2 database
- It runs `schema.sql` to create tables
- It runs `conditional-data.sql` to add sample users with roles

### 2. User Lookup Process
- During authentication, the app extracts the email from the Microsoft token
- `UserRepository` queries the database: `SELECT * FROM users WHERE name = ?`
- If the user is found, their roles determine what they can access
- If not found (rare case), there's a fallback mechanism

## Debug and Logging

- `DebugLogger` writes detailed logs to a file
- Log entries include timestamps and context
- The `/debug/logs` endpoint in `HomeController` displays these logs
- Authentication errors are displayed on the `/debug` page

## Component Interaction

1. **Configuration Classes** set up the framework and connect components
2. **Filters** intercept and process requests at specific points
3. **Services** contain the business logic for authentication
4. **Repository** handles data access
5. **Controllers** manage HTTP flow and view selection
6. **JSP Views** render the UI with user data

The application demonstrates a complete integration between Spring Security's authentication framework and Microsoft's OAuth 2.0 implementation, handling the entire lifecycle from login to logout with proper security measures.
