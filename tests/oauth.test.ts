import { describe, expect, it } from "vitest";
import {
  authorizationServerMetadata,
  isAcceptedOAuthResource,
  isChatGptRedirectUri,
  mcpAuthenticateChallenge,
  oauthUrls,
  protectedResourceMetadata
} from "../src/server/lib/oauth";

const publicUrl = "https://phosphene.example/app";

describe("ChatGPT OAuth metadata", () => {
  it("advertises protected-resource and authorization-server discovery", () => {
    expect(protectedResourceMetadata(publicUrl)).toEqual({
      resource: "https://phosphene.example/mcp",
      authorization_servers: ["https://phosphene.example"],
      scopes_supported: ["phosphene:ai"],
      bearer_methods_supported: ["header"],
      resource_documentation: "https://phosphene.example"
    });
    expect(authorizationServerMetadata(publicUrl)).toMatchObject({
      issuer: "https://phosphene.example",
      authorization_endpoint: "https://phosphene.example/oauth/authorize",
      token_endpoint: "https://phosphene.example/oauth/token",
      registration_endpoint: "https://phosphene.example/oauth/register",
      grant_types_supported: ["authorization_code", "refresh_token"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["none"]
    });
  });

  it("points 401 challenges at the path-specific resource metadata", () => {
    expect(mcpAuthenticateChallenge(publicUrl)).toBe(
      'Bearer resource_metadata="https://phosphene.example/.well-known/oauth-protected-resource/mcp", scope="phosphene:ai"'
    );
  });

  it("accepts the origin or MCP endpoint as the requested resource", () => {
    expect(isAcceptedOAuthResource(publicUrl, "https://phosphene.example")).toBe(true);
    expect(isAcceptedOAuthResource(publicUrl, "https://phosphene.example/mcp")).toBe(true);
    expect(isAcceptedOAuthResource(publicUrl, "https://evil.example/mcp")).toBe(false);
  });

  it("registers only exact ChatGPT OAuth callback origins", () => {
    expect(
      isChatGptRedirectUri("https://chatgpt.com/connector/oauth/callback-id")
    ).toBe(true);
    expect(
      isChatGptRedirectUri("https://chatgpt.com/connector_platform_oauth_redirect")
    ).toBe(true);
    expect(
      isChatGptRedirectUri("https://chatgpt.com.evil.example/connector/oauth/callback-id")
    ).toBe(false);
    expect(isChatGptRedirectUri("https://chatgpt.com/not-a-callback")).toBe(false);
  });

  it("normalizes all OAuth URLs to the configured public origin", () => {
    expect(oauthUrls(publicUrl)).toMatchObject({
      origin: "https://phosphene.example",
      resource: "https://phosphene.example/mcp"
    });
  });
});
