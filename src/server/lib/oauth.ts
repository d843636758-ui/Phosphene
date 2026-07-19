export const OAUTH_SCOPE = "phosphene:ai";

function publicOrigin(publicUrl: string): string {
  return new URL(publicUrl).origin;
}

export function oauthUrls(publicUrl: string) {
  const origin = publicOrigin(publicUrl);
  return {
    origin,
    resource: `${origin}/mcp`,
    protectedResourceMetadata: `${origin}/.well-known/oauth-protected-resource/mcp`,
    authorizationServerMetadata: `${origin}/.well-known/oauth-authorization-server`,
    authorizationEndpoint: `${origin}/oauth/authorize`,
    tokenEndpoint: `${origin}/oauth/token`,
    registrationEndpoint: `${origin}/oauth/register`
  };
}

export function protectedResourceMetadata(publicUrl: string) {
  const urls = oauthUrls(publicUrl);
  return {
    resource: urls.resource,
    authorization_servers: [urls.origin],
    scopes_supported: [OAUTH_SCOPE],
    bearer_methods_supported: ["header"],
    resource_documentation: urls.origin
  };
}

export function authorizationServerMetadata(publicUrl: string) {
  const urls = oauthUrls(publicUrl);
  return {
    issuer: urls.origin,
    authorization_endpoint: urls.authorizationEndpoint,
    token_endpoint: urls.tokenEndpoint,
    registration_endpoint: urls.registrationEndpoint,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
    scopes_supported: [OAUTH_SCOPE],
    client_id_metadata_document_supported: false
  };
}

export function mcpAuthenticateChallenge(publicUrl: string): string {
  const urls = oauthUrls(publicUrl);
  return `Bearer resource_metadata="${urls.protectedResourceMetadata}", scope="${OAUTH_SCOPE}"`;
}

export function isAcceptedOAuthResource(publicUrl: string, resource: string): boolean {
  const urls = oauthUrls(publicUrl);
  return resource === urls.resource || resource === urls.origin;
}

export function isChatGptRedirectUri(value: string): boolean {
  try {
    const url = new URL(value);
    if (url.origin !== "https://chatgpt.com") return false;
    return (
      url.pathname.startsWith("/connector/oauth/") ||
      url.pathname === "/connector_platform_oauth_redirect"
    );
  } catch {
    return false;
  }
}
