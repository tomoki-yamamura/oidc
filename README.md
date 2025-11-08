# OIDC Demo with Go and Google

OpenID Connect (OIDC) implementation using Google as the Identity Provider.

## Setup

1. Create OAuth2 credentials in Google Cloud Console
   - Add `http://localhost:8080/callback` to Authorized redirect URIs

2. Set environment variables
   ```bash
   cp .env.example .envrc
   # Edit .envrc file with actual values
   ```

3. Install dependencies
   ```bash
   go mod tidy
   ```

4. Run server
   ```bash
   source .env
   go run main.go
   ```

5. Access `http://localhost:8080` in your browser

## Endpoints

1. `/login` - Redirect to Google authentication page
2. `/callback` - Handle callback from Google
3. `/logout` - Logout
4. `/` - Home page (shows login status)

## Features

- OIDC authorization code flow
- ID Token verification
- Session management
- CSRF/replay attack prevention with state/nonce