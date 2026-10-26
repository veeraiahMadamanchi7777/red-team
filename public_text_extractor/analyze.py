#!/usr/bin/env python3
"""Passively identify a page's likely technology stack, visual design, and API surface."""

from __future__ import annotations

import argparse
import json
import re
import urllib.parse
from collections import Counter
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

try:
    from .extract import check_robots, fetch
except ImportError:  # Running as: python public_text_extractor/analyze.py ...
    from extract import check_robots, fetch


class AssetParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.scripts: list[str] = []
        self.stylesheets: list[str] = []
        self.inline_styles: list[str] = []
        self.inline_scripts: list[str] = []
        self._style = False
        self._script = False
        self._buffer: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {k.lower(): v or "" for k, v in attrs}
        if tag.lower() == "script":
            if values.get("src"):
                self.scripts.append(values["src"])
            else:
                self._script, self._buffer = True, []
        elif tag.lower() == "link" and "stylesheet" in values.get("rel", "").lower() and values.get("href"):
            self.stylesheets.append(values["href"])
        elif tag.lower() == "style":
            self._style, self._buffer = True, []

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "style" and self._style:
            self.inline_styles.append("".join(self._buffer))
            self._style = False
        elif tag.lower() == "script" and self._script:
            self.inline_scripts.append("".join(self._buffer))
            self._script = False

    def handle_data(self, data: str) -> None:
        if self._style or self._script:
            self._buffer.append(data)


# ─── Comprehensive stack detection patterns ────────────────────────────────────
# (regex, technology_name, layer, confidence)
STACK_PATTERNS: list[tuple[str, str, str, str]] = [

    # ── Frontend Frameworks ────────────────────────────────────────────────────
    (r"/_next/|__next_f\b|next/static|__NEXT_DATA__|next-router-prefetch|next\.config", "Next.js", "Frontend framework", "high"),
    (r"/_nuxt/|__NUXT__|nuxt\.config|nuxt-link|nuxt-img", "Nuxt.js", "Frontend framework", "high"),
    (r"__sveltekit|_app/immutable|sveltekit:scripts|svelte-kit", "SvelteKit", "Frontend framework", "high"),
    (r"__remixContext|__remixManifest|@remix-run", "Remix", "Frontend framework", "high"),
    (r"gatsby-image|__GATSBY|gatsby-plugin|/static/gatsby", "Gatsby", "Frontend framework", "high"),
    (r"astro-island|astro:scripts|@astrojs|/astro/", "Astro", "Frontend framework", "high"),
    (r"qwikloader|@builder\.io/qwik|qwik-city", "Qwik / Qwik City", "Frontend framework", "high"),
    (r"solid-js|createSignal.*solid|solid-start", "SolidJS", "Frontend framework", "medium"),
    (r"angular(?:\.min)?\.js|ng-version=|_ngcontent-|platformBrowserDynamic|@angular/core", "Angular", "Frontend library", "high"),

    # ── Frontend Libraries ─────────────────────────────────────────────────────
    (r"react(?:\.production|\.development)?(?:\.min)?\.js|data-reactroot|__react|ReactDOM|react-dom", "React", "Frontend library", "high"),
    (r"vue(?:\.runtime)?(?:\.global)?(?:\.min)?\.js|data-v-[0-9a-f]{8}|createApp.*vue|@vue/", "Vue.js", "Frontend library", "high"),
    (r"svelte(?:\.min)?\.js|data-svelte|SVELTE_HEAD", "Svelte", "Frontend library", "high"),
    (r"preact|preact/compat|h\(Fragment", "Preact", "Frontend library", "medium"),
    (r"jquery(?:\.min)?\.js|\$\(document\)\.ready|jQuery\.", "jQuery", "JavaScript library", "high"),
    (r"alpinejs|x-data=|x-init=|Alpine\.start", "Alpine.js", "JavaScript library", "high"),
    (r"htmx\.org|hx-get=|hx-post=|hx-target=", "HTMX", "JavaScript library", "high"),
    (r"stimulus|Stimulus\.Application|data-controller=", "Stimulus.js", "JavaScript library", "medium"),
    (r"lit-element|LitElement|@lit/|lit-html", "Lit", "Web components library", "high"),

    # ── State Management ───────────────────────────────────────────────────────
    (r"redux(?:-toolkit)?|createStore|combineReducers|@reduxjs|Redux DevTools", "Redux", "State management", "medium"),
    (r"mobx|makeObservable|observable.*action|@mobx-react", "MobX", "State management", "medium"),
    (r"zustand|createWithEqualityFn|from.*['\"]zustand['\"]", "Zustand", "State management", "medium"),
    (r"jotai|from.*['\"]jotai['\"]|useAtom\b", "Jotai", "State management", "medium"),
    (r"recoil|RecoilRoot|useRecoilState|from.*['\"]recoil['\"]", "Recoil", "State management", "medium"),
    (r"xstate|createMachine|useMachine.*xstate", "XState", "State management", "medium"),
    (r"@tanstack/react-query|react-query|QueryClientProvider|useQuery.*QueryClient", "TanStack Query", "Data fetching / cache", "high"),
    (r"from.*['\"]swr['\"]|useSWR\(", "SWR", "Data fetching / cache", "high"),
    (r"@apollo/client|ApolloProvider|InMemoryCache|useQuery.*apollo|gql`", "Apollo Client", "GraphQL client", "high"),
    (r"urql|createClient.*urql|from.*['\"]urql['\"]", "URQL", "GraphQL client", "medium"),

    # ── CSS Frameworks & UI Libraries ──────────────────────────────────────────
    (r"tailwindcss|tailwind\.config|--tw-[a-z]|class=[\"'][^\"']*(?:flex |grid |px-|py-|mx-|text-[a-z]{2,})", "Tailwind CSS", "CSS framework", "high"),
    (r"bootstrap(?:\.min)?\.css|bootstrap(?:\.min)?\.js|class=[\"'][^\"']*(?:btn btn-|col-md-|navbar-)", "Bootstrap", "CSS framework", "high"),
    (r"bulma(?:\.min)?\.css|class=[\"'][^\"']*(?:columns is-|button is-|hero is-)", "Bulma", "CSS framework", "medium"),
    (r"foundation(?:\.min)?\.css|class=[\"'][^\"']*(?:grid-x|cell small-|orbit)", "Foundation", "CSS framework", "medium"),
    (r"@mui/material|MuiButton|MuiContainer|makeStyles.*material|@emotion/", "Material UI (MUI)", "UI component library", "high"),
    (r"@chakra-ui|ChakraProvider|useColorMode.*chakra", "Chakra UI", "UI component library", "high"),
    (r"antd|ant-design|from.*['\"]antd['\"]|AntDesign", "Ant Design", "UI component library", "high"),
    (r"@radix-ui|radix-ui|RadixUI", "Radix UI", "UI component library", "high"),
    (r"shadcn|components/ui/button|components/ui/dialog", "shadcn/ui", "UI component library", "medium"),
    (r"@mantine/core|MantineProvider|from.*['\"]@mantine", "Mantine", "UI component library", "high"),
    (r"primereact|PrimeReact|primeng|p-button", "PrimeReact/NG", "UI component library", "medium"),
    (r"daisyui|daisy", "DaisyUI", "CSS component library", "medium"),
    (r"@headlessui|headlessui", "Headless UI", "UI component library", "high"),
    (r"styled-components|createGlobalStyle|css`[^`]+`.*styled|@emotion/styled", "styled-components / Emotion", "CSS-in-JS", "high"),

    # ── Build Tools & Bundlers ─────────────────────────────────────────────────
    (r"webpack(?:ChunkName|_require__|__webpack_modules__|\[webpack)", "Webpack", "Build tool / bundler", "high"),
    (r"/@vite/|__vite_is_modern_browser|from.*/@vite|vite\.config", "Vite", "Build tool / bundler", "high"),
    (r"ROLLUP_ASSET_URL|rollupPluginBabelHelpers", "Rollup", "Build tool / bundler", "medium"),
    (r"@parcel/|parcel-bundle", "Parcel", "Build tool / bundler", "medium"),
    (r"TURBOPACK|turbopack", "Turbopack", "Build tool / bundler", "high"),
    (r"create-react-app|react-scripts|REACT_APP_", "Create React App", "Scaffolding", "medium"),
    (r"T3 App|create-t3-app|@t3-oss", "T3 Stack", "Full-stack framework", "high"),

    # ── CMS & Content Platforms ────────────────────────────────────────────────
    (r"wp-content|wp-includes|wp-json|WordPress|xmlrpc\.php", "WordPress", "CMS", "high"),
    (r"drupal\.settings|Drupal\.|sites/default/files", "Drupal", "CMS", "high"),
    (r"joomla|/components/com_|/modules/mod_", "Joomla", "CMS", "high"),
    (r"contentful\.com|cdn\.contentful\.com|@contentful/rich-text", "Contentful", "Headless CMS", "high"),
    (r"sanity\.io|@sanity/client|sanityClient|studio\.sanity", "Sanity", "Headless CMS", "high"),
    (r"prismic\.io|@prismicio|prismic-dom", "Prismic", "Headless CMS", "high"),
    (r"strapi\.io|@strapi/|strapi-plugin", "Strapi", "Headless CMS", "high"),
    (r"ghost\.org|ghost-api|content\.ghost\.io", "Ghost", "CMS / Publishing", "high"),
    (r"shopify|cdn\.shopify\.com|Shopify\.|myshopify\.com", "Shopify", "E-commerce / CMS", "high"),
    (r"woocommerce|wc-ajax|woocommerce_params", "WooCommerce", "E-commerce", "high"),
    (r"squarespace|static1\.squarespace\.com|squarespace-cdn", "Squarespace", "Website builder", "high"),
    (r"wix\.com|static\.wix\.com|wixstatic\.com", "Wix", "Website builder", "high"),
    (r"webflow|\.webflow\.io|wf-form", "Webflow", "No-code CMS", "high"),
    (r"hubspot|hs-scripts|hs-analytics|__hstc=", "HubSpot CMS", "CMS / Marketing", "high"),
    (r"omniupdate|omni[ -]?cms|cms\.omniupdate\.com", "Omni CMS", "CMS", "high"),
    (r"t4_|terminalfour|cms\.isu\.edu", "TerminalFour", "CMS", "high"),
    (r"sitecore|SXA|/sitecore/(?!api)", "Sitecore", "CMS", "high"),
    (r"/etc\.clientlibs/|granite/utils|core/wcm/components|\.lc-[0-9a-f]{20,}-lc\.", "Adobe Experience Manager (AEM)", "CMS", "high"),
    (r"rum\.hlx\.page|helix-rum-js|hlx\.live|hlx\.page|adobeaemcloud\.com", "Adobe Franklin / Helix", "CMS", "high"),
    (r"storyblok|@storyblok/|storyblok-js", "Storyblok", "Headless CMS", "high"),
    (r"directus\.io|@directus/sdk", "Directus", "Headless CMS", "high"),
    (r"payload-cms|payloadcms|@payloadcms", "Payload CMS", "Headless CMS", "high"),

    # ── Backend / Server ───────────────────────────────────────────────────────
    (r"x-powered-by.*express\b|expressjs|express\.Router", "Express.js", "Backend framework", "high"),
    (r"x-powered-by.*php\b|\.php\b|phpsessid|php-fpm", "PHP", "Backend language", "high"),
    (r"x-powered-by.*asp\.net|\.aspx\b|__viewstate|asp\.net|dotnet", ".NET / ASP.NET", "Backend framework", "high"),
    (r"csrfmiddlewaretoken|django-admin|x-powered-by.*django", "Django", "Backend framework", "high"),
    (r"x-powered-by.*flask|flask\.debugtoolbar|werkzeug", "Flask", "Backend framework", "high"),
    (r"/docs#/|/redoc\b|/openapi\.json|fastapi", "FastAPI", "Backend framework", "high"),
    (r"rails|x-powered-by.*ruby|data-turbo|data-turbolinks", "Ruby on Rails", "Backend framework", "high"),
    (r"laravel_session|laravel|x-powered-by.*php.*laravel", "Laravel", "Backend framework", "medium"),
    (r"/actuator/health|x-application-context|spring.*boot", "Spring Boot", "Backend framework", "high"),
    (r"x-powered-by.*next\.js", "Next.js API Routes", "Backend framework", "high"),
    (r"x-powered-by.*fastify|fastify", "Fastify", "Backend framework", "high"),
    (r"@nestjs/|nest-factory|nestjs", "NestJS", "Backend framework", "medium"),
    (r"hono\.dev|x-powered-by.*hono", "Hono", "Backend framework", "medium"),
    (r"elixir|phoenix.*framework|x-powered-by.*phoenix", "Phoenix (Elixir)", "Backend framework", "high"),
    (r"x-powered-by.*gin|go-gin|gin-gonic", "Go / Gin", "Backend framework", "high"),
    (r"actix-web|x-powered-by.*actix|rocket\.rs", "Rust web framework", "Backend framework", "medium"),
    (r"convex\.dev|@convex-dev|ConvexProvider", "Convex", "Backend / BaaS", "high"),

    # ── API Paradigm ───────────────────────────────────────────────────────────
    (r"/graphql\b|graphiql|__APOLLO_STATE__|gql`|\bgql\s*`|graphql-tag", "GraphQL API", "API layer", "high"),
    (r"trpc|createTRPCClient|@trpc/client|/api/trpc", "tRPC", "API layer", "high"),
    (r"socket\.io|SocketIO|socket\.on\(|socket\.emit\(|io\.connect", "Socket.io", "Real-time / WebSocket", "high"),
    (r"new WebSocket\(|wss?://[^\s\"']+|ws-heartbeat", "WebSocket", "Real-time", "medium"),
    (r"grpc-web|@grpc/grpc-js|protobuf", "gRPC / Protobuf", "API layer", "high"),
    (r"/swagger(?:\.json|-ui)|swagger-ui|/api-docs|openapi\.json|/redoc", "OpenAPI / Swagger", "API documentation", "high"),
    (r"Server-Sent Events|EventSource\(|text/event-stream", "Server-Sent Events", "Real-time", "high"),
    (r"webhooks?|webhook-secret|X-Webhook-", "Webhooks", "Integration pattern", "medium"),

    # ── Database & Data Platform ───────────────────────────────────────────────
    (r"supabase\.co|supabase-js|createClient.*supabase|@supabase/", "Supabase", "Database / BaaS", "high"),
    (r"firebase(?:app|firestore|database)|initializeApp.*firebase|@firebase/", "Firebase / Firestore", "Database / BaaS", "high"),
    (r"neon\.tech|neondb|@neondatabase|ws://.*neon", "Neon Postgres", "Database", "high"),
    (r"planetscale|pscale|@planetscale/database", "PlanetScale", "Database (MySQL)", "high"),
    (r"mongodb\.com|mongoose|MongoClient|atlas\.mongodb", "MongoDB / Atlas", "Database", "high"),
    (r"@prisma/client|PrismaClient|prisma generate", "Prisma ORM", "Database ORM", "high"),
    (r"drizzle-orm|drizzle-kit|from.*['\"]drizzle-orm", "Drizzle ORM", "Database ORM", "high"),
    (r"redis|ioredis|RedisClient|upstash.*redis|@upstash/redis", "Redis / Upstash", "Cache / Database", "medium"),
    (r"turso\.tech|@libsql/client|libsql", "Turso (libSQL)", "Database", "high"),
    (r"airtable\.com|@airtable/blocks|Airtable\.", "Airtable", "Database / Spreadsheet", "high"),
    (r"notion\.so|@notionhq/client|notion-client", "Notion API", "CMS / Database", "high"),
    (r"pocketbase|PocketBase\(", "PocketBase", "Database / BaaS", "high"),
    (r"appwrite|@appwrite/|Client.*appwrite", "Appwrite", "Database / BaaS", "high"),

    # ── Authentication ─────────────────────────────────────────────────────────
    (r"auth0\.com|auth0-spa-js|@auth0/auth0|lock\.auth0", "Auth0", "Authentication", "high"),
    (r"okta\.com|@okta/okta-auth|okta-signin-widget|okta\.com/oauth2", "Okta", "Authentication / SSO", "high"),
    (r"clerk\.dev|clerk\.com|@clerk/nextjs|ClerkProvider|clerk\.loaded", "Clerk", "Authentication", "high"),
    (r"next-auth|NextAuth|/api/auth/(?:signin|signout|session)|authOptions", "NextAuth.js", "Authentication", "high"),
    (r"cognito|amazon-cognito|CognitoUser|aws-amplify.*auth", "AWS Cognito", "Authentication", "high"),
    (r"firebase.*auth|signInWithEmailAndPassword|GoogleAuthProvider.*firebase", "Firebase Auth", "Authentication", "high"),
    (r"keycloak|keycloak-js|keycloak\.init", "Keycloak", "Authentication / SSO", "high"),
    (r"supabase.*auth|supabase.*session|signInWithOAuth.*supabase", "Supabase Auth", "Authentication", "high"),
    (r"stytch|@stytch/stytch-react", "Stytch", "Authentication", "high"),
    (r"workos|@workos-inc", "WorkOS", "Enterprise SSO", "high"),
    (r"lucia-auth|@lucia-auth|Lucia\(", "Lucia Auth", "Authentication", "medium"),
    (r"passport\.js|passport-local|passportjs|require.*passport", "Passport.js", "Authentication", "medium"),
    (r"better-auth|@better-auth", "Better Auth", "Authentication", "medium"),

    # ── Cloud Infrastructure ───────────────────────────────────────────────────
    (r"s3\.amazonaws\.com|s3-website|execute-api\.amazonaws|\.s3\.", "AWS", "Cloud infrastructure", "high"),
    (r"cloudfront\.net|x-amz-cf-id|cloudfront", "Amazon CloudFront", "CDN", "high"),
    (r"\.vercel\.app|x-vercel-id|x-vercel-cache|_vercel|vercel\.com", "Vercel", "Hosting / Edge", "high"),
    (r"\.netlify\.app|netlify-identity|x-nf-request-id|netlify\.com", "Netlify", "Hosting / Edge", "high"),
    (r"\.pages\.dev|cf-ray|__cf_bm|__cfduid|cloudflare", "Cloudflare", "CDN / Edge", "high"),
    (r"\.fly\.dev|x-fly-request-id|fly\.io", "Fly.io", "Hosting", "high"),
    (r"\.onrender\.com|render\.com", "Render", "Hosting", "high"),
    (r"\.railway\.app|railway\.app", "Railway", "Hosting", "high"),
    (r"heroku|\.herokuapp\.com", "Heroku", "Hosting", "high"),
    (r"\.azurewebsites\.|x-azure-ref|blob\.core\.windows|azure\.com", "Microsoft Azure", "Cloud infrastructure", "high"),
    (r"\.run\.app|x-cloud-trace|x-google-backends", "Google Cloud Run", "Hosting", "high"),
    (r"firebase.*hosting|\.web\.app|\.firebaseapp\.com", "Firebase Hosting", "Hosting", "high"),
    (r"fastly\.net|x-fastly-request-id|x-cache.*FASTLY", "Fastly CDN", "CDN", "high"),
    (r"akamai|akamaized\.net|x-akamai-transformed", "Akamai CDN", "CDN", "high"),
    (r"imgix\.net|imgix\.com", "Imgix", "Image CDN", "high"),
    (r"cloudinary\.com|res\.cloudinary", "Cloudinary", "Media / Image CDN", "high"),
    (r"bunnycdn\.com|\.b-cdn\.net|bunny\.net", "Bunny CDN", "CDN", "high"),
    (r"aws-amplify|@aws-amplify|Amplify\.configure", "AWS Amplify", "Full-stack hosting", "high"),

    # ── Observability & Monitoring ─────────────────────────────────────────────
    (r"sentry\.io|@sentry/|Sentry\.init|sentry-browser|sentry_dsn", "Sentry", "Error tracking", "high"),
    (r"datadoghq\.com|DD_RUM|datadog-browser|dd-rum-js", "Datadog", "Observability / APM", "high"),
    (r"newrelic\.com|NREUM|newrelic\.agent", "New Relic", "APM / Observability", "high"),
    (r"logrocket|LogRocket\.init|@logrocket", "LogRocket", "Session replay", "high"),
    (r"fullstory|window\._fs_namespace|FS\.identify", "FullStory", "Session analytics", "high"),
    (r"hotjar|hjSetting|hjid|hj\(", "Hotjar", "Heatmaps / session replay", "high"),
    (r"posthog\.com|posthog\.init|@posthog/posthog-js", "PostHog", "Product analytics", "high"),
    (r"mixpanel\.com|mixpanel\.init|mixpanel\.track", "Mixpanel", "Product analytics", "high"),
    (r"amplitude\.com|amplitude\.getInstance|@amplitude/analytics", "Amplitude", "Product analytics", "high"),
    (r"segment\.com|analytics\.load|analytics\.identify|@segment/analytics", "Segment", "CDP / Data pipeline", "high"),
    (r"rudderstack|rudder-analytics|@rudderstack", "RudderStack", "CDP / Analytics", "high"),
    (r"gtag\(|googletagmanager|GTM-[A-Z0-9]{6}|google-analytics", "Google Analytics / GTM", "Analytics", "high"),
    (r"plausible\.io|plausible-analytics", "Plausible Analytics", "Privacy analytics", "high"),
    (r"matomo|piwik\.js|_paq\.push", "Matomo", "Self-hosted analytics", "high"),
    (r"opentelemetry|@opentelemetry/|otel-", "OpenTelemetry", "Observability", "high"),

    # ── Payments ──────────────────────────────────────────────────────────────
    (r"stripe\.com|Stripe\.|stripe-js|@stripe/stripe-js|pk_(?:live|test)_", "Stripe", "Payments", "high"),
    (r"braintree|braintreepayments\.com|Braintree\.", "Braintree", "Payments", "high"),
    (r"paypal\.com|paypal-sdk|PAYPAL\.apps|paypal-checkout", "PayPal", "Payments", "high"),
    (r"squareup\.com|@square/web-sdk|square-checkout", "Square", "Payments", "high"),
    (r"paddle\.com|Paddle\.Setup|@paddle/paddle-js", "Paddle", "Payments / Billing", "high"),
    (r"lemonsqueezy|lemon\.js|@lemonsqueezy", "Lemon Squeezy", "Payments / Billing", "high"),

    # ── Communication & Support ────────────────────────────────────────────────
    (r"intercom\.io|Intercom\(|intercomSettings|@intercom/messenger", "Intercom", "Customer support / chat", "high"),
    (r"zendesk\.com|zESettings|zopim|zendesk-chat", "Zendesk", "Customer support", "high"),
    (r"crisp\.chat|window\.\$crisp|CRISP_WEBSITE_ID", "Crisp", "Live chat", "high"),
    (r"tawk\.to|Tawk_API|\.tawk\.to", "Tawk.to", "Live chat", "high"),
    (r"hubspot.*chat|HubSpotConversations|hs-chat", "HubSpot Chat", "Live chat / CRM", "high"),
    (r"sendgrid\.com|@sendgrid/mail|sg_api_key", "SendGrid", "Email delivery", "high"),
    (r"mailchimp\.com|mc\.us[0-9]+\.list-manage|mailchimp", "Mailchimp", "Email marketing", "high"),
    (r"resend\.com|@resend/node|from.*['\"]resend['\"]", "Resend", "Email delivery", "high"),
    (r"postmark|@postmarkapp|postmark-sdk", "Postmark", "Email delivery", "high"),
    (r"twilio\.com|@twilio/|Twilio\.", "Twilio", "Communications API", "high"),
    (r"pusher\.com|@pusher/|Pusher\(", "Pusher", "Real-time / WebSocket", "high"),
    (r"ably\.io|ably-js|@ably/|Ably\.", "Ably", "Real-time messaging", "high"),

    # ── Feature Flags & Experimentation ───────────────────────────────────────
    (r"launchdarkly\.com|LDClient|@launchdarkly", "LaunchDarkly", "Feature flags", "high"),
    (r"split\.io|SplitFactory|@splitsoftware", "Split.io", "Feature flags", "high"),
    (r"statsig\.com|statsig-js|@statsig/js-client", "Statsig", "Feature flags / experimentation", "high"),
    (r"growthbook|GrowthBook|@growthbook/growthbook", "GrowthBook", "Feature flags / A/B testing", "high"),
    (r"optimizely|Optimizely\.push|@optimizely/optimizely-sdk", "Optimizely", "A/B testing", "high"),

    # ── Search ────────────────────────────────────────────────────────────────
    (r"algolia\.net|algoliasearch|@algolia|instantsearch", "Algolia", "Search", "high"),
    (r"elastic\.co|elasticsearch|@elastic/elasticsearch", "Elasticsearch", "Search", "high"),
    (r"typesense|typesense-instantsearch|@typesense/", "Typesense", "Search", "high"),
    (r"meilisearch|@meilisearch/meilisearch", "Meilisearch", "Search", "high"),

    # ── Maps ──────────────────────────────────────────────────────────────────
    (r"maps\.googleapis\.com|google\.maps\.|initMap\b", "Google Maps", "Maps", "high"),
    (r"mapbox\.com|mapboxgl|@mapbox/mapbox-gl", "Mapbox", "Maps", "high"),
    (r"leafletjs\.com|L\.map\(|leaflet\.css", "Leaflet.js", "Maps", "high"),

    # ── AI / LLM ──────────────────────────────────────────────────────────────
    (r"openai\.com|@openai/openai|openai\.createCompletion|gpt-[34o]", "OpenAI API", "AI / LLM", "high"),
    (r"anthropic\.com|@anthropic-ai|claude-[23]|claude-sonnet|claude-haiku", "Anthropic / Claude", "AI / LLM", "high"),
    (r"@vercel/ai|vercel-ai-sdk|useChat.*ai-sdk|useCompletion.*ai", "Vercel AI SDK", "AI integration", "high"),
    (r"langchain|@langchain/|langchainjs", "LangChain", "AI orchestration", "high"),
    (r"llama|ollama|llama-index|llama\.cpp", "LlamaIndex / Llama", "AI / LLM", "medium"),
    (r"huggingface\.co|@huggingface/|transformers\.js", "Hugging Face", "AI / ML", "high"),
    (r"replicate\.com|@replicate/client", "Replicate", "AI / ML inference", "high"),

    # ── Storage ───────────────────────────────────────────────────────────────
    (r"@upstash/|upstash\.io", "Upstash", "Serverless Redis / Queue", "high"),
    (r"@vercel/blob|vercel.*blob", "Vercel Blob", "File storage", "high"),
    (r"r2\.cloudflarestorage|@cloudflare/workers-types.*R2", "Cloudflare R2", "Object storage", "high"),
    (r"aws-sdk.*s3|s3Client|PutObjectCommand", "AWS S3", "Object storage", "medium"),

    # ── Queue / Background Jobs ───────────────────────────────────────────────
    (r"inngest|@inngest/client|InngestClient", "Inngest", "Background jobs / queue", "high"),
    (r"trigger\.dev|@trigger\.dev|TriggerClient", "Trigger.dev", "Background jobs", "high"),
    (r"qstash|@upstash/qstash", "QStash (Upstash)", "Message queue", "high"),
    (r"bull(?:mq)?|@bull-board|BullMQ", "BullMQ / Bull", "Job queue", "high"),

    # ── Consent Management ────────────────────────────────────────────────────
    (r"onetrust|OneTrust|OptanonWrapper|cookielaw\.org", "OneTrust", "Consent management", "high"),
    (r"cookiebot|Cookiebot\.com", "Cookiebot", "Consent management", "high"),
    (r"trustarc|truste\.com|TrustArc", "TrustArc", "Consent management", "high"),
    (r"osano\.com|OsanoCookieConsent", "Osano", "Consent management", "high"),
    (r"usercentrics|usercentrics\.eu|UC_UI", "Usercentrics", "Consent management", "high"),
    (r"termly\.io|Termly\.load", "Termly", "Consent management", "medium"),
    (r"consentmanager\.net|cmp-js|CmpApi", "consentmanager.net", "Consent management", "medium"),
    (r"didomi\.io|window\.didomi|Didomi", "Didomi", "Consent management", "high"),

    # ── Internationalization ──────────────────────────────────────────────────
    (r"i18next|react-i18next|@i18next/|i18n\.changeLanguage", "i18next", "Internationalization", "high"),
    (r"@formatjs/intl|react-intl|createIntl\b|IntlProvider", "FormatJS / react-intl", "Internationalization", "high"),
    (r"@lingui/|linguijs|i18n\.activate\b", "Lingui", "Internationalization", "high"),
    (r"vue-i18n|VueI18n|createI18n\b", "Vue I18n", "Internationalization", "high"),
    (r"next-intl|@next-intl/|NextIntlClientProvider", "next-intl", "Internationalization", "high"),
    (r"@angular/localize|LOCALE_ID.*angular", "Angular Localize", "Internationalization", "high"),
    (r"crowdin\.com|crowdin-widget", "Crowdin", "Translation / L10n", "high"),
    (r"weglot\.com|Weglot\.initialize|weglot-switcher", "Weglot", "Translation / L10n", "high"),
    (r"transifex\.com|transifex-live|@transifex/native", "Transifex", "Translation / L10n", "high"),
    (r"lokalise\.com|lokalise-js", "Lokalise", "Translation / L10n", "medium"),

    # ── Testing & Quality ─────────────────────────────────────────────────────
    (r"__coverage__|window\.__coverage__", "Istanbul / NYC (code coverage)", "Testing", "medium"),
    (r"cypress|window\.Cypress\b", "Cypress", "Testing", "medium"),
    (r"playwright|window\.__pw_|_playwright", "Playwright", "Testing", "medium"),
]


def evidence(text: str, source: str, findings: list[dict[str, str]]) -> None:
    """Scan text for known technology signatures and add to findings."""
    for pattern, technology, layer, confidence in STACK_PATTERNS:
        if re.search(pattern, text, re.I) and not any(x["technology"] == technology for x in findings):
            findings.append({"layer": layer, "technology": technology, "evidence": source, "confidence": confidence})


def unique_matches(pattern: str, text: str, limit: int = 12) -> list[str]:
    return list(dict.fromkeys(re.findall(pattern, text, re.I)))[:limit]


def detect_api_endpoints(html: str, js_text: str) -> list[dict[str, str]]:
    """Extract likely API endpoint patterns from HTML and JavaScript."""
    combined = html + "\n" + js_text
    seen: set[str] = set()
    endpoints: list[dict[str, str]] = []

    def add(path: str, source: str) -> None:
        norm = path.rstrip("/") or "/"
        if norm not in seen and len(norm) >= 3:
            seen.add(norm)
            endpoints.append({"path": norm, "source": source})

    # fetch / axios / XHR calls with explicit paths
    for m in re.finditer(r"""(?:fetch|axios\.(?:get|post|put|delete|patch)|XMLHttpRequest)\s*\(\s*[`'"](\/[^`'"#?\s]{2,80})[`'"]""", combined, re.I):
        add(m.group(1), "fetch/axios call")

    # Express-style route definitions
    for m in re.finditer(r"""(?:app|router)\.(?:get|post|put|delete|patch|all)\s*\([`'"](\/[^`'"]{2,80})[`'"]""", combined, re.I):
        add(m.group(1), "route definition")

    # Next.js / generic API routes embedded in strings
    for m in re.finditer(r"""[`'"](\/api\/[^`'"#?\s]{1,80})[`'"]""", combined, re.I):
        add(m.group(1), "API path string")

    # Environment variable patterns referencing API base URLs
    for m in re.finditer(r"""(?:API_URL|NEXT_PUBLIC_API|BASE_URL|API_BASE)\s*[=:]\s*[`'"](https?://[^`'"]+)[`'"]""", combined, re.I):
        add(m.group(1), "env API base URL")

    return endpoints[:40]


def analyze(url: str, body: bytes, response: dict[str, Any], max_bytes: int, fetch_styles: bool = True, extra_js: str = "") -> dict[str, Any]:
    html = body.decode("utf-8", errors="replace")
    assets = AssetParser()
    assets.feed(html)
    joined_assets = "\n".join(assets.scripts + assets.stylesheets)
    inline_js = "\n".join(assets.inline_scripts)
    findings: list[dict[str, str]] = []

    evidence(html, "HTML markup and inline content", findings)
    evidence(joined_assets, "Script and stylesheet paths", findings)
    evidence(inline_js, "Inline JavaScript", findings)
    if extra_js:
        evidence(extra_js, "Fetched JS bundles", findings)

    headers = response.get("headers") or {}
    server = response.get("server") or headers.get("server", "")
    powered_by = response.get("x_powered_by") or headers.get("x-powered-by", "")
    if server:
        findings.append({"layer": "Server", "technology": server, "evidence": "Server response header", "confidence": "medium"})
    if powered_by:
        findings.append({"layer": "Backend", "technology": powered_by, "evidence": "X-Powered-By response header", "confidence": "medium"})

    css = "\n".join(assets.inline_styles)
    base = urllib.parse.urljoin(response["final_url"], "/")
    css_urls: list[str] = []
    for raw in assets.stylesheets[:5] if fetch_styles else []:
        absolute = urllib.parse.urljoin(response["final_url"], raw)
        if urllib.parse.urlparse(absolute).netloc == urllib.parse.urlparse(base).netloc:
            css_urls.append(absolute)
            try:
                css_body, _ = fetch(absolute, 10, max_bytes // 2, "PublicTextExtractor/0.1 (single-page, user-initiated fetch)")
                css += "\n" + css_body.decode("utf-8", errors="replace")
            except Exception:
                pass

    colors = Counter(x.lower() for x in re.findall(r"#[0-9a-fA-F]{3,8}\b|rgba?\([^)]*\)|hsla?\([^)]*\)", css))
    fonts = list(dict.fromkeys(re.findall(r"font-family\s*:\s*([^;}{]+)", css, re.I)))[:10]
    breakpoints = unique_matches(r"@media[^{}]*?(?:min-width|max-width)\s*:\s*([\d.]+(?:px|em|rem))", css)
    spacing = unique_matches(r"(?:margin|padding|gap)\s*:\s*([^;}{]+)", css, 10)
    design = {
        "palette": [{"value": value, "occurrences": count} for value, count in colors.most_common(12)],
        "typography": {"font_families": fonts, "font_size_tokens": unique_matches(r"font-size\s*:\s*([^;}{]+)", css, 12)},
        "layout": {"breakpoints": breakpoints, "spacing_examples": spacing, "layout_systems": [name for name, pattern in [("CSS Grid", r"display\s*:\s*grid"), ("Flexbox", r"display\s*:\s*flex"), ("container queries", r"@container")] if re.search(pattern, css, re.I)]},
        "ui_clues": {"border_radii": unique_matches(r"border-radius\s*:\s*([^;}{]+)", css, 10), "shadows": unique_matches(r"box-shadow\s*:\s*([^;}{]+)", css, 8), "icons_or_svg": bool(re.search(r"<svg|icon|fontawesome|lucide|material-icons|heroicons|phosphor", html + css, re.I))},
        "css_sources_checked": css_urls,
        "note": "Design values are inferred from accessible HTML/CSS; JavaScript-rendered styles require a real browser.",
    }

    api_endpoints = detect_api_endpoints(html, inline_js + "\n" + extra_js)

    return {
        "source_url": url,
        "response": response,
        "stack": findings,
        "design": design,
        "assets": {"scripts": assets.scripts, "stylesheets": assets.stylesheets},
        "api_endpoints": api_endpoints,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url")
    parser.add_argument("--out", type=Path, default=Path("public_text_reports/latest"))
    args = parser.parse_args()
    agent = "PublicTextExtractor/0.1 (single-page, user-initiated fetch)"
    allowed = check_robots(args.url, agent)
    if allowed is False:
        parser.error("robots.txt disallows fetching this URL")
    body, response = fetch(args.url, 15, 5_000_000, agent)
    result = analyze(args.url, body, response, 5_000_000)
    result["robots_allowed"] = allowed
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "technology_and_design.json").write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    lines = ["# Technology and Design Audit", "", f"Source: {args.url}", "", "## Technology stack", "", "| Layer | Technology | Evidence | Confidence |", "|---|---|---|---|"]
    lines.extend(f"| {x['layer']} | {x['technology']} | {x['evidence']} | {x['confidence']} |" for x in result["stack"])
    lines.extend(["", "## Design audit", "", f"- Palette: {', '.join(x['value'] for x in result['design']['palette']) or 'No CSS color tokens detected'}", f"- Fonts: {', '.join(result['design']['typography']['font_families']) or 'No font-family declarations detected'}", f"- Layout systems: {', '.join(result['design']['layout']['layout_systems']) or 'No grid/flex clues detected'}", f"- Responsive breakpoints: {', '.join(result['design']['layout']['breakpoints']) or 'None detected'}", f"- Icon/SVG clues: {'yes' if result['design']['ui_clues']['icons_or_svg'] else 'no'}", "", result['design']['note'], ""])
    (args.out / "technology_and_design.md").write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote {args.out / 'technology_and_design.md'} and {args.out / 'technology_and_design.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
