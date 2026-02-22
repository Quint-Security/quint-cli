export interface OAuthProvider {
  name: string;
  authUrl: string;
  tokenUrl: string;
  defaultScopes: string[];
  docs: string;
}

export const PROVIDERS: Record<string, OAuthProvider> = {
  github: {
    name: "GitHub",
    authUrl: "https://github.com/login/oauth/authorize",
    tokenUrl: "https://github.com/login/oauth/access_token",
    defaultScopes: ["repo", "read:org"],
    docs: "https://github.com/settings/developers",
  },
  notion: {
    name: "Notion",
    authUrl: "https://api.notion.com/v1/oauth/authorize",
    tokenUrl: "https://api.notion.com/v1/oauth/token",
    defaultScopes: [],
    docs: "https://www.notion.so/my-integrations",
  },
  slack: {
    name: "Slack",
    authUrl: "https://slack.com/oauth/v2/authorize",
    tokenUrl: "https://slack.com/api/oauth.v2.access",
    defaultScopes: ["chat:write", "channels:read"],
    docs: "https://api.slack.com/apps",
  },
  sentry: {
    name: "Sentry",
    authUrl: "https://sentry.io/oauth/authorize/",
    tokenUrl: "https://sentry.io/oauth/token/",
    defaultScopes: ["project:read", "event:read"],
    docs: "https://sentry.io/settings/developer-settings/",
  },
};

export function getProvider(name: string): OAuthProvider | undefined {
  return PROVIDERS[name.toLowerCase()];
}
