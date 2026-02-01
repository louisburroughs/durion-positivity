# durion-positivity Component

**The Central Integration Bridge Between Moqui Frontend and Durion POS Backend Microservices**

---

## Purpose

The `durion-positivity` component is the **single point of integration** for all authenticated calls from the Moqui frontend to the Durion POS Backend (`durion-positivity-backend`). It provides:

1. **Centralized API Gateway Interface** — Unified client for all backend REST services
2. **Token Management** — Issues and manages JWT assertions per ADR-0011 security architecture
3. **Request Orchestration** — Handles routing, error mapping, retry logic, and request logging
4. **Authentication Boundary** — Implements gateway-based security model (see **Architecture** section)
5. **Service Discovery** — Coordinates with backend API Gateway for service routing
6. **Domain Integration** — Exposes services consumed by other frontend components (CRM, Inventory, Orders, etc.)

**Key Principle:** ⚠️ **ALL authenticated calls from durion-moqui-frontend to durion-positivity-backend MUST route through this component's services. No direct HTTP calls allowed.**

---

## Architecture & Security Model

### ADR-0011: API Gateway Security Architecture

The Durion platform implements a **centralized gateway-based security model** (ADR-0011) that establishes clear trust boundaries and eliminates circular dependencies:

```
┌────────────────────────────────────────────────────────────────┐
│  Moqui Frontend (System of Record for User Identity)           │
│                                                                │
│  1. Authenticate user (login, session)                         │
│  2. Issue cryptographically signed JWT assertions              │
│     (HMAC-SHA256 with shared secret)                           │
│  3. Include claims: userId, roles, iat, exp, jti              │
└─────────────────────┬──────────────────────────────────────────┘
                      │
                      │ Assertion in Authorization: Bearer header
                      │ (via AssertionService.issue#JwtAssertion)
                      v
┌────────────────────────────────────────────────────────────────┐
│  Durion POS API Gateway (Authentication Enforcement Boundary)  │
│                                                                │
│  1. Extract JWT from Authorization header                      │
│  2. Verify signature using shared secret (HMAC-SHA256)        │
│  3. Validate claims (iss, aud, exp, sub, roles, jti)         │
│  4. Perform replay detection using jti                        │
│  5. Map Moqui roles → Spring authorities                      │
│  6. Create authenticated SecurityContext                      │
│  7. Forward to backend service                                │
└─────────────────────┬──────────────────────────────────────────┘
                      │
                      │ Request with authenticated principal
                      │ (X-User-Id, X-Authorities headers)
                      v
┌────────────────────────────────────────────────────────────────┐
│  Backend Microservices (pos-order, pos-inventory, etc.)       │
│                                                                │
│  1. Trust gateway as authentication boundary                   │
│  2. Use @PreAuthorize for fine-grained authorization          │
│  3. Do NOT call external services for identity validation     │
│  4. Access authenticated user via SecurityContext             │
└────────────────────────────────────────────────────────────────┘
```

### Token Structure (JWT Claims)

Assertions issued by `AssertionService.issue#JwtAssertion` contain:

| Claim | Value | Purpose |
|-------|-------|---------|
| `iss` | `"moqui"` | Issuer identifier |
| `aud` | `"api-gateway:<env>"` | Audience (gateway target) |
| `sub` | `<userId>` | Authenticated Moqui user |
| `roles` | `[list of Moqui roles]` | User's role assignments |
| `iat` | `<epoch seconds>` | Issued-at timestamp |
| `exp` | `<epoch seconds>` | Expiration (iat + TTL, default 900s) |
| `jti` | `<UUID>` | Unique token ID for replay detection |
| `tenantId` | `<optional>` | Multi-tenant context |
| `storeId` | `<optional>` | Store context |

**Example Header & Payload:**

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtb3F1aSIsImF1ZCI6ImFwaS1nYXRld2F5Omxvb2FsIiwic3ViIjoiam9obi5kb2UiLCJyb2xlcyI6WyJTSE9QX01HUiIsIlNBTEVTX1VTRVIiXSwiaWF0IjoxNzM4NDE1MjAwLCJleHAiOjE3Mzg0MTUzMDB9.xxx...
```

### Shared Secret

- **Generated in:** Moqui runtime configuration
- **Stored in:** Environment variable `MOQUI_ASSERTION_SECRET` or system property `moqui.assertion.secret`
- **Also provisioned to:** API Gateway via `MOQUI_ASSERTION_SECRET` environment variable
- **Algorithm:** HMAC-SHA256
- **Minimum length:** 32 characters
- **Never:** Transmitted in requests/responses or logged

**Configuration Example:**

```bash
# .env or deployment secrets
MOQUI_ASSERTION_SECRET="your-min-32-character-shared-secret-key-here"
MOQUI_ASSERTION_ISSUER="moqui"
MOQUI_ASSERTION_AUDIENCE="api-gateway:local"  # or "api-gateway:prod"
MOQUI_ASSERTION_TTL=900  # 15 minutes
```

---

## ⚠️ Mandatory Rule: All Authenticated Calls via durion-positivity

### The Rule

**Any authenticated HTTP call from the Moqui frontend to the `durion-positivity-backend` MUST be routed through a service in this component.** This ensures:

- ✅ **Centralized token management** — Assertions issued consistently
- ✅ **Unified error handling** — HTTP errors mapped to Moqui messages
- ✅ **Request logging & observability** — All backend calls auditable
- ✅ **Authentication boundary isolation** — Clear separation of concerns
- ✅ **Architectural integrity** — No direct backend dependencies

### What This Means

**❌ FORBIDDEN:**

```groovy
// ❌ DO NOT: Direct fetch/axios calls from components
def response = new URL("http://localhost:8081/v1/customers/123").openConnection().getInputStream()

// ❌ DO NOT: Hardcoded backend URLs in Vue components
const response = await fetch(`${BACKEND_URL}/v1/orders`)

// ❌ DO NOT: Manual JWT token handling in Vue
const token = localStorage.getItem('jwt_token')  // Bypass Moqui assertion issuance
```

**✅ REQUIRED:**

```groovy
// ✅ DO: Call durion-positivity service
def result = ec.service.sync()
    .name("durion.positivity.CrmRestServices.search#CommercialAccounts")
    .parameters([partyNumber: "ACC-001"])
    .call()

def accountId = result.partyId
```

```typescript
// ✅ DO: Use durion-positivity composable
import { usePosCustomerService } from '@/composables/useBackendService'

const { searchAccounts } = usePosCustomerService()
const accounts = await searchAccounts({ partyNumber: 'ACC-001' })
```

### Non-Authenticated Calls (Public APIs)

Calls to **public APIs without authentication** (rare) may bypass this rule if:

1. The endpoint is explicitly public (no `@PreAuthorize` in backend)
2. It's documented in the backend API contract as public
3. You notify the architecture team

Example: `/v1/health` or `/v1/public/catalog/categories`

---

## Component Structure

```plaintext
durion-positivity/
├── README.md                       # This file
├── component.xml                   # Moqui component metadata
├── service/                        # Core integration services
│   ├── AssertionServices.xml       # JWT assertion issuance (CAP-275)
│   ├── CrmRestServices.xml         # pos-customer API wrappers
│   ├── OrderRestServices.xml       # pos-order API wrappers
│   ├── InventoryRestServices.xml   # pos-inventory API wrappers
│   ├── CatalogRestServices.xml     # pos-catalog API wrappers
│   ├── ShopMgrRestServices.xml     # pos-shop-manager API wrappers
│   ├── AccountingRestServices.xml  # pos-accounting API wrappers
│   └── *.xml                       # Additional domain services
├── entity/                         # Supporting entity definitions
│   ├── AssertionEntities.xml       # Assertion audit trail entities
│   └── *.xml                       # Other entity models
├── test/                           # Unit and integration tests
│   ├── AssertionServicesTests.groovy
│   └── *.groovy
└── webapp/                         # Frontend Vue components (optional)
    ├── types/                      # TypeScript definitions
    ├── composables/                # Vue 3 composables
    └── *.vue                       # Vue 3 components
```

---

## Key Services

### JWT Assertion Issuance

**Service:** `durion.positivity.AssertionServices.issue#JwtAssertion`

Issues a signed JWT assertion for the current authenticated user.

**Input:**
- `tenantId` (optional) — Multi-tenant context
- `storeId` (optional) — Store context
- `additionalClaims` (optional) — Custom claims map

**Output:**
- `token` — Compact JWT string
- `jti` — Token ID for audit/tracing
- `expiresAt` — Expiration timestamp

**Usage:**

```groovy
def result = ec.service.sync()
    .name("durion.positivity.AssertionServices.issue#JwtAssertion")
    .parameters([tenantId: "TENANT_001", storeId: "STORE_123"])
    .call()

String jwtToken = result.token
```

### Authenticated Backend Calls

**Service:** `durion.positivity.AssertionServices.call#BackendApi`

Convenience wrapper that issues an assertion and makes an authenticated HTTP request to the backend.

**Input:**
- `baseUrl` — Backend service URL (e.g., `http://localhost:8081`)
- `path` — API path (e.g., `/v1/customers/123`)
- `method` — HTTP method (GET, POST, PUT, DELETE, PATCH)
- `body` (optional) — Request body for POST/PUT
- `queryParams` (optional) — Query parameters
- `tenantId` (optional) — Tenant context
- `storeId` (optional) — Store context
- `timeoutMs` (default 30000) — Request timeout

**Output:**
- `statusCode` — HTTP status
- `responseBody` — Parsed response
- `headers` — Response headers
- `success` — Boolean success flag
- `errorMessage` (on error) — Error details

**Usage:**

```groovy
def result = ec.service.sync()
    .name("durion.positivity.AssertionServices.call#BackendApi")
    .parameters([
        baseUrl: "http://localhost:8081",
        path: "/v1/customers",
        method: "GET",
        queryParams: [limit: 10, offset: 0]
    ])
    .call()

if (result.success) {
    def customers = result.responseBody
} else {
    ec.message.addError(result.errorMessage)
}
```

### Domain-Specific REST Wrappers

Each domain has corresponding REST wrapper services (e.g., `CrmRestServices`, `OrderRestServices`). These wrap backend API endpoints and provide Moqui service interfaces.

**Naming Pattern:** `{Domain}RestServices.xml`

**Service Verbs:** `create#`, `update#`, `delete#`, `get#`, `search#`

**Example CRM Service:**

```groovy
def result = ec.service.sync()
    .name("durion.positivity.CrmRestServices.search#CommercialAccounts")
    .parameters([
        partyNumber: "ACC-001",
        limit: 20,
        offset: 0
    ])
    .call()

// Result contains: partyId, accounts[], totalCount
```

---

## Configuration

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `MOQUI_ASSERTION_SECRET` | Yes | — | HMAC shared secret (32+ chars) |
| `MOQUI_ASSERTION_ISSUER` | No | `moqui` | Token issuer identifier |
| `MOQUI_ASSERTION_AUDIENCE` | No | `api-gateway:local` | Token audience |
| `MOQUI_ASSERTION_TTL` | No | `900` | Token TTL in seconds (60-3600) |
| `MOQUI_ASSERTION_ENABLED` | No | `true` | Enable/disable assertion issuance |
| `MOQUI_ASSERTION_AUDIT_ENABLED` | No | `false` | Enable audit logging |
| `POS_CUSTOMER_URL` | No | `http://localhost:8081` | pos-customer base URL |
| `POS_ORDER_URL` | No | `http://localhost:8081` | pos-order base URL |
| `POS_INVENTORY_URL` | No | `http://localhost:8081` | pos-inventory base URL |
| `POS_CATALOG_URL` | No | `http://localhost:8081` | pos-catalog base URL |
| `POS_SHOP_MGR_URL` | No | `http://localhost:8081` | pos-shop-manager base URL |
| `POS_ACCOUNTING_URL` | No | `http://localhost:8081` | pos-accounting base URL |

### Local Development

Create a `.env` file in the Moqui runtime root:

```bash
MOQUI_ASSERTION_SECRET="dev-secret-key-minimum-32-characters-long-for-hmac"
MOQUI_ASSERTION_ISSUER="moqui"
MOQUI_ASSERTION_AUDIENCE="api-gateway:local"
MOQUI_ASSERTION_TTL=900
MOQUI_ASSERTION_ENABLED=true
MOQUI_ASSERTION_AUDIT_ENABLED=true

POS_CUSTOMER_URL=http://localhost:8081
POS_ORDER_URL=http://localhost:8081
POS_INVENTORY_URL=http://localhost:8081
```

---

## Integration Points

### 1. From Other Components

Other Moqui components (durion-crm, durion-inventory, durion-order, etc.) call durion-positivity services:

```groovy
// From durion-crm component
def result = ec.service.sync()
    .name("durion.positivity.CrmRestServices.search#CommercialAccounts")
    .parameters([partyNumber: accountNumber])
    .call()
```

### 2. From Vue Components

Frontend Vue 3 components use composables that wrap durion-positivity services:

```typescript
// Vue component
import { usePosCustomerService } from '@/composables/useBackendService'

const { searchAccounts } = usePosCustomerService()

onMounted(async () => {
  const accounts = await searchAccounts({ partyNumber: 'ACC-001' })
})
```

### 3. Backend API Gateway Validation

The `durion-positivity-backend` API Gateway validates JWT assertions:

```java
// In pos-api-gateway/SecurityGatewayConfig.java
@Bean
public SecurityWebFilterChain securityWebFilterChain(
        ServerHttpSecurity http,
        JwtTokenValidator jwtValidator) {
    
    return http
        .authorizeExchange()
            .pathMatchers("/actuator/health", "/v1/public/**").permitAll()
            .anyExchange().authenticated()
        .and()
        .oauth2ResourceServer()
            .jwt()
                .jwtAuthenticationConverter(jwtValidator)
        .and()
        .build();
}
```

---

## API Contract

### Request/Response Pattern

All service wrappers follow a consistent pattern:

**Request:**
```groovy
Map params = [
    // business parameters
    partyNumber: "ACC-001",
    
    // optional pagination
    limit: 20,
    offset: 0,
    
    // optional sorting
    orderBy: "partyNumber",
    orderByDir: "asc"
]
```

**Response:**
```groovy
[
    success: true,
    message: "Operation successful",
    
    // single-item operations
    partyId: "P1001",
    
    // list operations
    items: [...],
    totalCount: 150,
    
    // error case
    errorCode: "CUSTOMER_NOT_FOUND",
    errorMessage: "Customer with partyNumber ACC-001 not found"
]
```

### Error Mapping

HTTP errors from backend are mapped to Moqui error messages:

| HTTP Status | Moqui Error Code | Message |
|-------------|-----------------|---------|
| 400 | `VALIDATION_ERROR` | Bad request / invalid parameters |
| 401 | `AUTHENTICATION_ERROR` | Unauthorized (token invalid/expired) |
| 403 | `AUTHORIZATION_ERROR` | Forbidden (insufficient permissions) |
| 404 | `NOT_FOUND_ERROR` | Resource not found |
| 409 | `CONFLICT_ERROR` | Resource conflict (e.g., duplicate) |
| 500 | `BACKEND_ERROR` | Backend service error |

---

## Testing

### Unit Tests

Run Spock tests for assertion services:

```bash
cd durion-moqui-frontend
./gradlew test --tests "*AssertionServices*"
```

### Integration Tests

Test backend API calls:

```bash
./gradlew test --tests "*RestServices*"
```

### Configuration for Tests

Tests use a test configuration file (loaded before integration tests):

```groovy
System.setProperty('moqui.assertion.secret', 'test-secret-key-minimum-32-characters')
System.setProperty('moqui.assertion.issuer', 'test-moqui')
System.setProperty('moqui.assertion.audience', 'api-gateway:test')
```

---

## Related Documentation

- **ADR-0011:** [API Gateway Security Architecture](../../docs/adr/0011-api-gateway-security-architecture.adr.md)
- **ADR-0010:** [Frontend Domain Responsibilities Guide](../../docs/adr/0010-frontend-domain-responsibilities-guide.adr.md)
- **Backend:** [durion-positivity-backend AGENTS.md](../../../durion-positivity-backend/AGENTS.md)
- **Security:** [Durion Security Guide](../../docs/governance/SECURITY.md)

---

## Troubleshooting

### Assertion Issuance Fails

**Error:** `MOQUI_ASSERTION_SECRET_UNAVAILABLE`

**Solution:** Verify `MOQUI_ASSERTION_SECRET` environment variable is set:

```bash
echo $MOQUI_ASSERTION_SECRET  # Should print key (don't log in prod!)
```

### Backend Call Returns 401 Unauthorized

**Error:** Token invalid or expired

**Solution:**
1. Verify shared secret matches between Moqui and API Gateway
2. Check token TTL hasn't expired: `MOQUI_ASSERTION_TTL=900` (adjust as needed)
3. Ensure user is authenticated in Moqui session
4. Check API Gateway logs for replay detection failures

### Backend Call Returns 403 Forbidden

**Error:** User lacks required permissions

**Solution:**
1. Verify user's roles in Moqui user group assignments
2. Check backend `@PreAuthorize` annotation against mapped roles
3. Ensure roles are included in JWT assertion claims

### Direct HTTP Calls Not Working

**Error:** Services fail because component bypassed

**Solution:** Use durion-positivity services instead of direct HTTP calls:

```groovy
// ❌ Wrong
def url = "http://localhost:8081/v1/customers"
def result = new URL(url).text

// ✅ Correct
def result = ec.service.sync()
    .name("durion.positivity.CrmRestServices.search#CommercialAccounts")
    .call()
```

---

## Support

For issues or questions:

1. Check related ADRs: ADR-0011 (Security), ADR-0010 (Frontend Domains)
2. Review backend API documentation: `durion-positivity-backend/docs/`
3. Check component-specific tests in `test/` directory
4. Consult architecture team in `durion/docs/AGENT_COLLABORATION.md`

