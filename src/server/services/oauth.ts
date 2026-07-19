import { createHash, timingSafeEqual } from "node:crypto";
import { and, eq, gt, isNull } from "drizzle-orm";
import { Router, type Request, type Response } from "express";
import rateLimit from "express-rate-limit";
import { z } from "zod";
import { config } from "../config";
import { getDb } from "../db/client";
import {
  oauthAuthorizationCodes,
  oauthClients,
  oauthTokens
} from "../db/schema";
import { AppError } from "../errors";
import { createId, createSecret, tokenHash } from "../lib/ids";
import {
  authorizationServerMetadata,
  isAcceptedOAuthResource,
  isChatGptRedirectUri,
  OAUTH_SCOPE,
  oauthUrls,
  protectedResourceMetadata
} from "../lib/oauth";
import { verifyPassword } from "./auth";

const authorizationCodeLifetimeMs = 10 * 60 * 1000;
const accessTokenLifetimeMs = 60 * 60 * 1000;
const refreshTokenLifetimeMs = 90 * 24 * 60 * 60 * 1000;

const oauthLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 60,
  standardHeaders: "draft-8",
  legacyHeaders: false
});

const registrationSchema = z.object({
  client_name: z.string().min(1).max(120).default("ChatGPT"),
  redirect_uris: z.array(z.string().url()).min(1).max(8),
  token_endpoint_auth_method: z.literal("none").default("none"),
  grant_types: z
    .array(z.enum(["authorization_code", "refresh_token"]))
    .default(["authorization_code", "refresh_token"]),
  response_types: z.array(z.literal("code")).default(["code"])
});

const authorizationRequestSchema = z.object({
  response_type: z.literal("code"),
  client_id: z.string().min(1).max(500),
  redirect_uri: z.string().url(),
  code_challenge: z.string().min(43).max(128),
  code_challenge_method: z.literal("S256"),
  state: z.string().max(2048).optional(),
  resource: z.string().url().optional(),
  scope: z.string().max(256).optional()
});

const authorizationDecisionSchema = authorizationRequestSchema.extend({
  password: z.string().min(1).max(256).optional(),
  decision: z.enum(["approve", "deny"])
});

const tokenRequestSchema = z.discriminatedUnion("grant_type", [
  z.object({
    grant_type: z.literal("authorization_code"),
    code: z.string().min(1).max(512),
    client_id: z.string().min(1).max(500),
    redirect_uri: z.string().url(),
    code_verifier: z.string().min(43).max(128),
    resource: z.string().url().optional()
  }),
  z.object({
    grant_type: z.literal("refresh_token"),
    refresh_token: z.string().min(1).max(512),
    client_id: z.string().min(1).max(500),
    resource: z.string().url().optional(),
    scope: z.string().max(256).optional()
  })
]);

type AuthorizationRequest = z.infer<typeof authorizationRequestSchema>;

function htmlEscape(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function hiddenField(name: string, value: string | undefined): string {
  return value == null
    ? ""
    : `<input type="hidden" name="${htmlEscape(name)}" value="${htmlEscape(value)}">`;
}

function normalizeScope(value: string | undefined): string {
  const scopes = (value ?? OAUTH_SCOPE).split(/\s+/).filter(Boolean);
  if (scopes.length === 0 || scopes.some((scope) => scope !== OAUTH_SCOPE)) {
    throw new AppError(400, "invalid_scope", "The requested OAuth scope is not supported");
  }
  return OAUTH_SCOPE;
}

function normalizeResource(value: string | undefined): string {
  const resource = value ?? oauthUrls(config.PUBLIC_URL).resource;
  if (!isAcceptedOAuthResource(config.PUBLIC_URL, resource)) {
    throw new AppError(400, "invalid_target", "The requested OAuth resource is not supported");
  }
  return resource;
}

async function validateAuthorizationRequest(input: AuthorizationRequest) {
  const client = await getDb().query.oauthClients.findFirst({
    where: eq(oauthClients.clientId, input.client_id)
  });
  if (!client) throw new AppError(400, "invalid_client", "OAuth client is not registered");
  if (!client.redirectUris.includes(input.redirect_uri)) {
    throw new AppError(400, "invalid_redirect_uri", "OAuth redirect URI is not registered");
  }
  return {
    client,
    scope: normalizeScope(input.scope),
    resource: normalizeResource(input.resource)
  };
}

function authorizationRedirect(
  redirectUri: string,
  values: Record<string, string | undefined>
): string {
  const redirect = new URL(redirectUri);
  for (const [key, value] of Object.entries(values)) {
    if (value != null) redirect.searchParams.set(key, value);
  }
  return redirect.toString();
}

function renderAuthorizationPage(
  response: Response,
  input: AuthorizationRequest,
  clientName: string,
  error?: string
) {
  const redirectOrigin = new URL(input.redirect_uri).origin;
  response.set({ "Cache-Control": "no-store", Pragma: "no-cache" });
  response.status(error ? 401 : 200).type("html").send(`<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>连接 Phosphene</title>
  <style>
    body{font-family:system-ui,sans-serif;max-width:34rem;margin:3rem auto;padding:0 1rem;line-height:1.55;color:#171717}
    main{border:1px solid #ddd;border-radius:16px;padding:1.5rem}
    label{display:block;margin:1rem 0 .35rem}input[type=password]{box-sizing:border-box;width:100%;padding:.8rem;border:1px solid #aaa;border-radius:10px}
    .actions{display:flex;gap:.75rem;margin-top:1.25rem}button{padding:.75rem 1rem;border-radius:10px;border:1px solid #999;background:#fff}button[value=approve]{background:#171717;color:#fff;border-color:#171717}
    .error{color:#b42318}.muted{color:#666;font-size:.92rem}
  </style>
</head>
<body><main>
  <h1>连接 Phosphene</h1>
  <p><strong>${htmlEscape(clientName)}</strong> 请求代表你的 AI 读取和管理 Phosphene 任务、积分与奖励。</p>
  <p class="muted">授权完成后将返回 ${htmlEscape(redirectOrigin)}。请只在你刚刚从 ChatGPT 发起连接时继续。</p>
  ${error ? `<p class="error">${htmlEscape(error)}</p>` : ""}
  <form method="post" action="/oauth/authorize">
    ${hiddenField("response_type", input.response_type)}
    ${hiddenField("client_id", input.client_id)}
    ${hiddenField("redirect_uri", input.redirect_uri)}
    ${hiddenField("code_challenge", input.code_challenge)}
    ${hiddenField("code_challenge_method", input.code_challenge_method)}
    ${hiddenField("state", input.state)}
    ${hiddenField("resource", input.resource)}
    ${hiddenField("scope", input.scope)}
    <label for="password">Phosphene 登录密码</label>
    <input id="password" name="password" type="password" autocomplete="current-password" required maxlength="256">
    <div class="actions">
      <button type="submit" name="decision" value="approve">允许连接</button>
      <button type="submit" name="decision" value="deny" formnovalidate>拒绝</button>
    </div>
  </form>
</main></body></html>`);
}

function pkceChallenge(verifier: string): string {
  return createHash("sha256").update(verifier).digest("base64url");
}

function constantTimeEqual(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  return (
    leftBuffer.length === rightBuffer.length &&
    timingSafeEqual(leftBuffer, rightBuffer)
  );
}

function tokenResponse(
  response: Response,
  accessToken: string,
  refreshToken: string,
  scope: string
) {
  response.set({ "Cache-Control": "no-store", Pragma: "no-cache" });
  response.json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: Math.floor(accessTokenLifetimeMs / 1000),
    refresh_token: refreshToken,
    scope
  });
}

function oauthError(response: Response, status: number, error: string, description: string) {
  response.set({ "Cache-Control": "no-store", Pragma: "no-cache" });
  response.status(status).json({ error, error_description: description });
}

export async function verifyOAuthAccessToken(rawToken: string): Promise<boolean> {
  const token = await getDb().query.oauthTokens.findFirst({
    where: and(
      eq(oauthTokens.accessTokenHash, tokenHash(rawToken)),
      isNull(oauthTokens.revokedAt),
      gt(oauthTokens.accessExpiresAt, new Date())
    )
  });
  if (!token) return false;
  await getDb()
    .update(oauthTokens)
    .set({ lastUsedAt: new Date() })
    .where(eq(oauthTokens.id, token.id));
  return true;
}

export function createOAuthRouter(): Router {
  const router = Router();

  router.get("/.well-known/oauth-protected-resource", (_request, response) => {
    response.json(protectedResourceMetadata(config.PUBLIC_URL));
  });
  router.get("/.well-known/oauth-protected-resource/mcp", (_request, response) => {
    response.json(protectedResourceMetadata(config.PUBLIC_URL));
  });
  router.get("/.well-known/oauth-authorization-server", (_request, response) => {
    response.json(authorizationServerMetadata(config.PUBLIC_URL));
  });

  router.post("/oauth/register", oauthLimiter, async (request, response) => {
    try {
      const input = registrationSchema.parse(request.body);
      if (!input.redirect_uris.every(isChatGptRedirectUri)) {
        oauthError(
          response,
          400,
          "invalid_redirect_uri",
          "Only ChatGPT connector OAuth redirect URIs are accepted"
        );
        return;
      }
      if (!input.grant_types.includes("authorization_code")) {
        oauthError(response, 400, "invalid_client_metadata", "Authorization code grant is required");
        return;
      }
      const clientId = `phosphene_client_${createSecret(24)}`;
      await getDb().insert(oauthClients).values({
        clientId,
        clientName: input.client_name,
        redirectUris: input.redirect_uris
      });
      response.status(201).json({
        client_id: clientId,
        client_id_issued_at: Math.floor(Date.now() / 1000),
        client_name: input.client_name,
        redirect_uris: input.redirect_uris,
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"]
      });
    } catch (error) {
      if (error instanceof z.ZodError) {
        oauthError(response, 400, "invalid_client_metadata", "OAuth client metadata is invalid");
        return;
      }
      throw error;
    }
  });

  router.get("/oauth/authorize", oauthLimiter, async (request, response) => {
    try {
      const input = authorizationRequestSchema.parse(request.query);
      const { client } = await validateAuthorizationRequest(input);
      renderAuthorizationPage(response, input, client.clientName);
    } catch (error) {
      response.status(400).type("text").send(
        error instanceof AppError || error instanceof Error
          ? error.message
          : "OAuth authorization request is invalid"
      );
    }
  });

  router.post("/oauth/authorize", oauthLimiter, async (request, response) => {
    let input: z.infer<typeof authorizationDecisionSchema>;
    try {
      input = authorizationDecisionSchema.parse(request.body);
      const { client, scope, resource } = await validateAuthorizationRequest(input);
      if (input.decision === "deny") {
        response.redirect(
          303,
          authorizationRedirect(input.redirect_uri, {
            error: "access_denied",
            error_description: "The user denied the Phosphene connection",
            state: input.state
          })
        );
        return;
      }
      try {
        await verifyPassword(input.password ?? "");
      } catch {
        renderAuthorizationPage(response, input, client.clientName, "密码不正确，请重试。");
        return;
      }
      const code = `phosphene_code_${createSecret(32)}`;
      await getDb().insert(oauthAuthorizationCodes).values({
        id: createId("oauthcode"),
        codeHash: tokenHash(code),
        clientId: input.client_id,
        redirectUri: input.redirect_uri,
        codeChallenge: input.code_challenge,
        scope,
        resource,
        expiresAt: new Date(Date.now() + authorizationCodeLifetimeMs)
      });
      response.redirect(
        303,
        authorizationRedirect(input.redirect_uri, { code, state: input.state })
      );
    } catch (error) {
      response.status(400).type("text").send(
        error instanceof AppError || error instanceof Error
          ? error.message
          : "OAuth authorization request is invalid"
      );
    }
  });

  router.post("/oauth/token", oauthLimiter, async (request, response) => {
    let input: z.infer<typeof tokenRequestSchema>;
    try {
      input = tokenRequestSchema.parse(request.body);
    } catch {
      oauthError(response, 400, "invalid_request", "OAuth token request is invalid");
      return;
    }

    if (input.grant_type === "authorization_code") {
      const code = await getDb().query.oauthAuthorizationCodes.findFirst({
        where: and(
          eq(oauthAuthorizationCodes.codeHash, tokenHash(input.code)),
          eq(oauthAuthorizationCodes.clientId, input.client_id),
          isNull(oauthAuthorizationCodes.usedAt),
          gt(oauthAuthorizationCodes.expiresAt, new Date())
        )
      });
      if (
        !code ||
        code.redirectUri !== input.redirect_uri ||
        !constantTimeEqual(pkceChallenge(input.code_verifier), code.codeChallenge) ||
        (input.resource != null && input.resource !== code.resource)
      ) {
        oauthError(response, 400, "invalid_grant", "Authorization code is invalid or expired");
        return;
      }
      const accessToken = `phosphene_oauth_${createSecret(32)}`;
      const refreshToken = `phosphene_refresh_${createSecret(32)}`;
      const issued = await getDb().transaction(async (tx: any) => {
        const [claimed] = await tx
          .update(oauthAuthorizationCodes)
          .set({ usedAt: new Date() })
          .where(
            and(
              eq(oauthAuthorizationCodes.id, code.id),
              isNull(oauthAuthorizationCodes.usedAt)
            )
          )
          .returning({ id: oauthAuthorizationCodes.id });
        if (!claimed) return false;
        await tx.insert(oauthTokens).values({
          id: createId("oauthtoken"),
          accessTokenHash: tokenHash(accessToken),
          refreshTokenHash: tokenHash(refreshToken),
          clientId: code.clientId,
          scope: code.scope,
          resource: code.resource,
          accessExpiresAt: new Date(Date.now() + accessTokenLifetimeMs),
          refreshExpiresAt: new Date(Date.now() + refreshTokenLifetimeMs)
        });
        return true;
      });
      if (!issued) {
        oauthError(response, 400, "invalid_grant", "Authorization code was already used");
        return;
      }
      tokenResponse(response, accessToken, refreshToken, code.scope);
      return;
    }

    const current = await getDb().query.oauthTokens.findFirst({
      where: and(
        eq(oauthTokens.refreshTokenHash, tokenHash(input.refresh_token)),
        eq(oauthTokens.clientId, input.client_id),
        isNull(oauthTokens.revokedAt),
        gt(oauthTokens.refreshExpiresAt, new Date())
      )
    });
    if (
      !current ||
      (input.resource != null && input.resource !== current.resource) ||
      (input.scope != null && normalizeScope(input.scope) !== current.scope)
    ) {
      oauthError(response, 400, "invalid_grant", "Refresh token is invalid or expired");
      return;
    }
    const accessToken = `phosphene_oauth_${createSecret(32)}`;
    const refreshToken = `phosphene_refresh_${createSecret(32)}`;
    const [rotated] = await getDb()
      .update(oauthTokens)
      .set({
        accessTokenHash: tokenHash(accessToken),
        refreshTokenHash: tokenHash(refreshToken),
        accessExpiresAt: new Date(Date.now() + accessTokenLifetimeMs),
        refreshExpiresAt: new Date(Date.now() + refreshTokenLifetimeMs),
        lastUsedAt: new Date()
      })
      .where(
        and(
          eq(oauthTokens.id, current.id),
          eq(oauthTokens.refreshTokenHash, tokenHash(input.refresh_token)),
          isNull(oauthTokens.revokedAt)
        )
      )
      .returning({ id: oauthTokens.id });
    if (!rotated) {
      oauthError(response, 400, "invalid_grant", "Refresh token was already used");
      return;
    }
    tokenResponse(response, accessToken, refreshToken, current.scope);
  });

  return router;
}
