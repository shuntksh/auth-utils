# Example Implementation

## Authentication Flow

The OIDC authentication flow is a choreographed sequence of requests and responses between your application, the user, and the identity provider.

1. **Sign-in Initiation**:
   - User clicks "Sign in with Google" button
   - Frontend makes request to `/api/auth/login/google`
   - Backend generates PKCE parameters (code verifier and challenge)
   - Backend generates state and nonce for security
   - Backend redirects to Google's authorization endpoint with these parameters

2. **Google Authentication**:
   - User authenticates with Google (enters credentials if not already logged in)
   - Google validates the request parameters
   - Google redirects back to your callback URL with an authorization code

3. **Token Exchange & Validation**:
   - Backend receives the authorization code
   - Backend verifies the state parameter to prevent CSRF attacks
   - Backend exchanges code for tokens using the code verifier (PKCE)
   - Backend validates ID token signature using provider's JWK set
   - Backend verifies token claims (issuer, audience, expiration)
   - Backend verifies nonce to prevent replay attacks

4. **User Creation/Retrieval**:
   - Backend extracts the user identifier (sub claim) from the ID token
   - Backend checks if a user with this identifier exists in the database
   - Creates new user record if first time sign-in
   - Retrieves existing user if returning

5. **Session Creation**:
   - Backend creates a new session record
   - Backend sets a secure session cookie
   - Backend redirects to protected area of the application

## 1. Configuration Setup

In OIDC, each provider requires specific configuration parameters to establish secure communication. This includes endpoints for authorization, token exchange, and user information retrieval.

Create a configuration file `app/lib/auth-config.ts`:

```typescript
import { OIDCProviderConfig } from '@workspace/auth';

export const googleConfig: OIDCProviderConfig = {
  provider: 'google',
  issuer: 'https://accounts.google.com',
  clientId: process.env.GOOGLE_CLIENT_ID!,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
  redirectUri: `${process.env.NEXT_PUBLIC_BASE_URL}/api/auth/callback/google`,
  authorizationEndpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
  tokenEndpoint: 'https://oauth2.googleapis.com/token',
  userInfoEndpoint: 'https://openidconnect.googleapis.com/v1/userinfo',
  jwksUri: 'https://www.googleapis.com/oauth2/v3/certs',
  defaultScopes: ['openid', 'email', 'profile'],
  usePKCE: true
};
```

## 2. Authentication Routes

OIDC authentication follows a specific flow involving multiple HTTP redirects and secure token exchanges. The following routes handle the different stages of this process.

### Login Route (`app/api/auth/login/google/route.ts`):

This route initiates the authentication process by generating security parameters and redirecting to the provider's authorization endpoint.

```typescript
import { OIDC, PKCE } from '@workspace/auth';
import { cookies } from 'next/headers';

export async function GET() {
  // Generate PKCE parameters for enhanced security
  // PKCE prevents authorization code interception attacks
  const pkce = await PKCE.generate();
  
  // Generate state for CSRF protection
  // This random value will be verified when the user returns to prevent cross-site request forgery
  const state = crypto.randomUUID();
  
  // Generate nonce for replay protection
  // This will be included in the ID token and verified to prevent token replay attacks
  const nonce = crypto.randomUUID();
  
  // Store PKCE, state and nonce in cookies
  const cookieStore = cookies();
  cookieStore.set('oauth_state', state, { httpOnly: true, secure: true });
  cookieStore.set('oauth_nonce', nonce, { httpOnly: true, secure: true });
  cookieStore.set('oauth_code_verifier', pkce.codeVerifier, { httpOnly: true, secure: true });

  // Create authentication URL with all necessary parameters
  const authUrl = OIDC.createAuthenticationUrl({
    config: googleConfig,
    state,
    nonce,
    pkce,
  });

  // Redirect to Google login
  return Response.redirect(authUrl);
}
```

### Callback Route (`app/api/auth/callback/google/route.ts`):

This route handles the provider's response, exchanges the authorization code for tokens, validates the tokens, and establishes a user session.

```typescript
import { OIDC, PKCE } from '@workspace/auth';
import { cookies } from 'next/headers';

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const code = searchParams.get('code');
  const state = searchParams.get('state');
  
  if (!code) {
    return new Response('Missing code parameter', { status: 400 });
  }

  const cookieStore = cookies();
  const storedState = cookieStore.get('oauth_state')?.value;
  const nonce = cookieStore.get('oauth_nonce')?.value;
  const codeVerifier = cookieStore.get('oauth_code_verifier')?.value;

  // Verify state to prevent CSRF
  if (state !== storedState) {
    return new Response('Invalid state', { status: 400 });
  }

  try {
    // Exchange code for tokens and validate ID token
    // This step verifies the code using PKCE, exchanges it for tokens,
    // and validates the ID token signature and claims
    const { tokens, idTokenClaims } = await OIDC.handleAuthenticationResponse({
      config: googleConfig,
      code,
      codeVerifier, // The code verifier from PKCE
      nonce,
    });

    // Fetch additional user info if needed
    const userInfo = await OIDC.fetchUserInfo({
      config: googleConfig,
      accessToken: tokens.access_token,
    });

    // For sign-up flow: Find or create user
    // Implementation depends on your database/user management system
    const user = await findOrCreateUser({
      sub: idTokenClaims!.sub, // Unique Google ID
      email: userInfo.email!,
      name: userInfo.name,
      picture: userInfo.picture,
    });

    // Create session
    const session = await createSession({
      userId: user.id,
      // Store refresh token if you want to implement token refresh
      refreshToken: tokens.refresh_token,
    });

    // Clear OAuth cookies
    cookieStore.delete('oauth_state');
    cookieStore.delete('oauth_nonce');
    cookieStore.delete('oauth_code_verifier');

    // Set session cookie
    cookieStore.set('session_id', session.id, {
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      maxAge: 60 * 60 * 24 * 7, // 1 week
    });

    // Redirect to dashboard or home page
    return Response.redirect('/dashboard');

  } catch (error) {
    console.error('Authentication error:', error);
    return Response.redirect('/auth/error');
  }
}
```

## Security Considerations

OIDC implementations must address several security concerns to protect user data and prevent common attacks:

- **Always use HTTPS in production**: Prevents man-in-the-middle attacks and token theft
- **Store tokens securely**: Use httpOnly cookies to prevent JavaScript access
- **Implement CSRF protection**: Validate the state parameter in the callback
- **Validate all tokens and claims**: Verify signatures, issuer, audience, and expiration
- **Use PKCE**: Prevents authorization code interception, especially important for public clients
- **Implement proper session management**: Secure cookies with appropriate flags
- **Consider token refresh mechanisms**: Securely handle refresh tokens for long-lived sessions
- **Validate redirect URIs**: Only accept pre-registered redirect URIs

## Error Handling

A robust OIDC implementation must handle various error scenarios gracefully:

- **Invalid/expired tokens**: Redirect to login or refresh tokens
- **Network errors**: Provide clear error messages and retry mechanisms
- **User cancellation**: Handle cases where users deny consent
- **Invalid state/nonce**: Detect potential attacks and respond appropriately
- **Token validation failures**: Log security events and take appropriate action

## Additional Features

Consider implementing these advanced features for a more complete authentication system:

- **Token refresh mechanism**: Automatically refresh expired access tokens
- **Session revocation**: Allow users to log out from all devices
- **Account linking**: Connect multiple social accounts to a single user
- **Multi-provider support**: Allow login via different OIDC providers
- **Remember me functionality**: Extend session duration for trusted devices

