---
'@repo/mcp-common': patch
'cloudflare-ai-gateway-mcp-server': patch
'auditlogs': patch
'cloudflare-autorag-mcp-server': patch
'cloudflare-browser-mcp-server': patch
'cloudflare-blog': patch
'cloudflare-casb-mcp-server': patch
'demo-day': patch
'dex-analysis': patch
'dns-analytics': patch
'docs-ai-search': patch
'graphql-mcp-server': patch
'logpush': patch
'cloudflare-radar-mcp-server': patch
'containers-mcp': patch
'stack-mcp': patch
'workers-bindings': patch
'workers-builds': patch
'workers-observability': patch
---

Enable 30-day sliding refresh token expiry (`refreshTokenIdleTTL: 2_592_000`) in `createCloudflareOAuthRouter` so active MCP sessions extend their grant expiry on refresh instead of hitting a hard 30-day cliff and failing to renew 90-day dynamic OAuth client registrations.
