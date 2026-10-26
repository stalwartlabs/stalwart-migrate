# Schema changes: v0.16 to v1.0

Scope: structural differences between the Stalwart v0.16.27 and v1 configuration schemas. For the meaning of each setting, see the Stalwart documentation.

## 0. Method and legend

- Baseline: the v0.16.27 schema. Target: the v1 schema (Enterprise edition; the open-source edition omits the enterprise items listed in 1.3).
- Both schemas were compared structurally (objects, properties, flags, variants and group variants), together with the numeric id lists, the permissions and the telemetry definitions. Every rename was confirmed against the history of the schema.
- The compiled v0.16.27 schema omits the 14 `_reserved_*` `Locale` placeholders that the v0.16 source schema still defines; the `Locale` counts in this document include them (see section 4).
- Most renames keep the same description text. The following 18 were matched even though the description changed: `address->host`, `addresses->hosts`, `brokers->hosts`, `apiKey->apiKeyId`, `apiUser->username`, `secretId->accessKeyId`, `secretApiKey->secret`, `autoUpdateFrequency->autoUpdateInterval`, `trainFrequency->trainInterval`, `concurrency->maxConcurrentRequests`, `maxConcurrent->maxConcurrentConnections`, `maxRequestRate->rateLimit`, `maxRetries->maxPolls`, `timeout->connectTimeout`, `dnsRbl->spamLookup`, `logoUrl->logo`, `requireAudience->acceptedAudiences`, `SenderAuth.dkimSignDomain` (moved). Removals that have no rename (`accessKey`/`sasToken` of Azure, `email`, `secret`, `threadPoolSize`, `useXForwarded`, OIDC provider fields, ...) are classified as restructured or removed in 3.2 and 3.4.
- Schema snapshots: `mapping/schema/v0.16.27.json.gz` (v0.16.27) and `mapping/schema/v1.json.gz` / `v1_oss.json.gz` (v1 Enterprise and open-source editions). The schema comparison over the snapshots gives 171 removed and 237 added properties in schemas present in both versions and 7 type changes in shared property names; a completeness check verifies that `mapping/v016_to_v1.toml` covers every removal, type change and changed default.
- Names are JMAP/registry property names (camelCase). Rust struct fields are snake_case of the same name.
- Rename confidence: **[C]** confirmed (the old field was removed and the new one added in the same change with identical type/flags/default, or the change is explicit); **[L]** likely (shape matches, semantics shifted or only inferred); **[U]** uncertain (do not map automatically without review).
- `T|null` = nullable, `T[]` = list, `K[V]` = map. `(E)` = enterprise-only.

## 1. Cross-cutting changes

### 1.1 Numeric ids renumbered (raw registry copy is unsafe)

All numeric id spaces were re-sorted/renumbered, not only appended to:

| Id space | Old entries | New entries | Shared names | Shared names with a different id |
|---|---|---|---|---|
| Server objects | 117 | 120 | 116 | 68 |
| Server properties | 935 | 1011 | 853 | 836 |
| Server permissions | 661 | 643 | 624 | 561 |
| User properties | 47 | 48 | 47 | 33 |

- Event ids: 558 of the 585 shared events changed id; metric ids: 290 events changed `metric-id`. See section 6.
- Positional ids (enum variants and group variants) were compacted where retired entries were deleted, so every later variant's discriminant shifted. Example: `DnsServerType` is `Deprecated1 = 1, Cloudflare = 2, DigitalOcean = 3, DeSEC = 4` in v0.16 and `Cloudflare = 1, DigitalOcean = 2, DeSEC = 3` in v1; in v0.16 `DnsServerBootstrapType` has `Deprecated1 = 2, Cloudflare = 3`.
- Affected positional lists: `DnsServer` group (71 -> 70), `Task` group (18 -> 18, 3 removed and 3 appended), `Locale` (336 -> 322, the 14 `_reserved_*` placeholders removed), `ExpressionConstant` (19 -> 13), `ExpressionVariable` (92 -> 94), `Dkim2Flag` (3 -> 1), `TaskStoreMaintenanceType` (15 -> 14), `SearchEmailField` (12 -> 8), `SearchCalendarField` (7 -> 5), `SearchContactField` (11 -> 10).
- Consequence: any copy must go through names (v0.16 types -> v1 types), never through raw ids.

### 1.2 Serialization is now declared per object

Every stored object/singleton now declares a serialization mode, and v1 tracks the storage slot of each field and the record version of packed objects explicitly (v0.16 had neither).

- `extensible`: all configuration and registry-stored objects (default).
- `packed`: `Trace`, `Metric` (high-volume telemetry; positional records, both at record version 0).
- `none` (not stored in registry format): `DataStore`, `Bootstrap`, `AccountSettings`, `AccountPassword`, `ApiKey`, `AppPassword`, `Log`, `QueuedMessage`, `ClusterNode`, `Action`, `IndexQueueStatus` (new).
- All 25 `version` / `deprecated` field markers of v0.16 are gone (v1 has none; the slot layout restarts in v1). Affected fields stay in the schema except those listed as removed in 3.4.
- Retired stored fields of v0.16 (deprecated, `no-store`, `hide:ui`) were deleted from the schema: `DnsServerCloudflare.email`, `DnsServerDnsimple.secret`; `DnsServerPorkbun.secret` was retired in v0.16 and the name `secret` is reused for the live field (see 3.1).

### 1.3 Enterprise gating added

Newly enterprise-only (available only in the Enterprise edition; the open-source schema omits them):

- Objects: `Metric` (`Trace` was already enterprise in v0.16).
- Fields: `memberTenantId` on `DnsServerCommon`, `GroupAccount`, `MailingList`, `OAuthClient`, `Role`, `UserAccount`; `Cache.tenants`; `LdapDirectory.urlFailover` (new, enterprise).
- Group/enum variants: `BlobStore.Sharded@ShardedBlobStore`, `InMemoryStore.Sharded@ShardedInMemoryStore`, `LookupStore.Sharded@ShardedInMemoryStore`, `Task.RestoreArchivedItem`, `Task.TenantMaintenance`, `TaskStoreMaintenanceType.reindexTelemetry`, `TaskStoreMaintenanceType.resetTenantQuotas`, `StorageQuota.maxMaskedAddresses`.
- Permissions: `interactAi`, `Live.tracing`, `Live.metrics`, `Scim.access`.
- Events: `Ai.LlmResponse`, `Ai.ApiError`, `Limit.TenantQuota`, `Server.Licensing`, `Telemetry.AlertEvent`, `Telemetry.AlertMessage`, `Telemetry.MetricsStored`.

### 1.4 `no-operations` flags (permissions removed)

Objects that lost operations (the matching `sys<Object>Create|Update|Destroy|Get|Query` permissions no longer exist, see section 5):

| Object | Operations removed |
|---|---|
| `Action` | get, update, destroy, query |
| `ArchivedItem` | create |
| `ArfExternalReport`, `DmarcExternalReport`, `TlsExternalReport` | create, update |
| `DmarcInternalReport`, `TlsInternalReport` | create |
| `ClusterNode` | create, update, destroy |
| `Log`, `Trace`, `Metric` | create, update, destroy |
| `QueuedMessage` | create |
| `SpamTrainingSample` | update |
| `IndexQueueStatus` (new) | create, destroy |
| `OAuthGrant` (new) | create, update |

### 1.5 Shared base `HttpClient` (settings)

`HttpClient` (own: `timeout` default `"30s"`, `allowInvalidCerts` default `false`; parent `HttpRequestHeaders`: `httpAuth`, `httpHeaders`) now backs more objects:

| Object | Old parent | New parent | Net effective field change |
|---|---|---|---|
| `AsnResource` | `HttpRequestHeaders` | `HttpClient` | + `allowInvalidCerts` |
| `HttpLookup` | none | `HttpClient` | + `httpAuth`, `httpHeaders`, `allowInvalidCerts` (own `timeout` moved to parent, same default) |
| `MetricsOtelHttp` | `HttpRequestHeaders` | `HttpClient` | + `allowInvalidCerts` |
| `MtaHook` | `HttpRequestHeaders` | `HttpClient` | none (own `timeout`, `allowInvalidCerts` moved to parent, same defaults) |
| `WebHook` | `TracerCommon + HttpRequestHeaders` | `TracingEventSelection + HttpClient` | none (own `enable`, `level`, `lossy` declared on `WebHook`; `timeout`, `allowInvalidCerts` from parent) |
| `TracerOtelHttp` | `TracerOtelCommon` | `TracerOtelCommon` | + `allowInvalidCerts` (declared directly) |
| `AiModel` | `HttpRequestHeaders` | none (see 2.3) | restructured |

### 1.6 Naming conventions applied in v1

Useful to pattern-match renames not listed explicitly: `enabled`/`isEnabled` -> `enable`; `*Frequency`/`*Interval` -> `*Interval`; `xMaxY` -> `maxXY`; `timeoutX` -> `xTimeout`; `capacityX` -> `xCapacity`; `endpoint`/`baseUrl`/`customEndpoint` -> `url`; `addresses`/`brokers`/`hostname`/`address` (server names) -> `hosts`/`host`; `accessKey`/`apiKey` -> `accessKeyId`/`apiKeyId`; `authToken` -> `token`; `sourceIp(s)` -> `localIp(s)`; `envFrom`/`envRcptTo` -> `mailFrom`/`rcptTo`.

## 2. Objects

### 2.1 New objects (registry objects/singletons)

| Name | Kind | Fields |
|---|---|---|
| `SpamAi` | singleton (E) | group `Disable` / `Enable@SpamAiProperties`; replaces `SpamLlm` (see 2.3) |
| `Metadata` | singleton | `dataTypes: MetadataDataType[]` (default all 8), `vendorNamespaces: Boolean` (true), `privateMetadata: Boolean` (true), `maxDepth: UnsignedInt\|null` (8), `maxEntrySize: Size` (8192), `maxSize: Size` (65536), `maxPrivateSize: Size` (16384), `maxEntries: UnsignedInt` (128), `maxQueryScan: UnsignedInt` (50000), `imapServerComment: Text\|null`, `imapServerAdmin: Uri\|null` |
| `OAuthGrant` | object (`filter-account`, `sequential-id`, plural "connected applications") | `accountId: @Account`, `clientId: String`, `clientName: String\|null`, `clientKind: OAuthClientKind`, `scopes: OAuthScope[]`, `remoteIp: IpAddr\|null`, `createdAt`, `lastUsedAt: UTCDateTime`, `generation: UnsignedInt` (0), `pending: Boolean` (false) |
| `IndexQueueStatus` | object, serialization none | `index: IndexType`, `partition: UnsignedInt` (0), `queuedUpdates: UnsignedInt` (0), `queuedDeletions: UnsignedInt` (0), `status: IndexStatus` (group `Running` / `Failed@IndexStatusFailed{reason: Text, nextRetry: UTCDateTime}`) |

`SpamAiProperties` fields: `mode: SpamAiMode` (Automatic), `condition: Expression` (default expression over `spam_score`/`spam_threshold`/`spam_probability`), `tiers: SpamAiTier[]` (min 1), `instructions: Text` (long default), `categories: SpamAiCategory[]`, `signals: SpamAiSignal[]`, `bucketHigh` 0.85, `bucketMedium` 0.65, `uncertainBelow` 0.3, `verbalHigh` 0.9, `verbalMedium` 0.7, `verbalLow` 0.55, `explanation` false, `addHeader` true, `maxInputChars` 6000, `maxLinks` 20, `maxAttachments` 10, `trimQuotes` true, `includeAuth` true, `includeLinks` true, `includeAttachments` true, `deadline` "10s", `breakerThreshold` 5, `breakerCooldown` "1m", `learn: SpamAiLearn` (group `Disable` / `Enable@{minProbability 0.95, sampleRate 0.1}`), `webSearch: SpamAiWebSearch` (group `Disable` / ...).

### 2.2 Removed objects

| Name | Replacement |
|---|---|
| `SpamLlm` (singleton, E) | `SpamAi` [C] (renamed; payload redesigned, see 2.3) |

### 2.3 Renamed, moved, merged, split

| Change | Detail | Confidence |
|---|---|---|
| `SpamLlm` -> `SpamAi`; `SpamLlmProperties` -> `SpamAiProperties` | Group variants `Disable`/`Enable` kept (positions 0/1), form label "LLM Classifier" -> "AI Classifier". Payload redesigned: old fields `categories: String[]` (default Unsolicited, Commercial, Harmful, Legitimate), `confidence: String[]` (High, Medium, Low), `responsePosCategory: UnsignedInt` (0), `responsePosConfidence: UnsignedInt\|null` (1), `responsePosExplanation: UnsignedInt\|null` (2), `modelId: @AiModel`, `prompt: Text`, `separator: String` (","), `temperature: Float` (0.5) all removed. `modelId` -> `tiers[].modelId` (`SpamAiTier{modelId, escalateBelow, escalateOn}`) [L]. `prompt` -> `instructions` [U, different contract: v0.16 parsed a delimited text response, v1 uses structured categories/signals]. `categories: String[]` -> `categories: SpamAiCategory[]{name, description, includes}` [L, type change]. | [C] rename, [L]/[U] field mapping |
| `AiModel`: one flat object -> group by provider | Old: `AiModel: HttpRequestHeaders{name, url: Uri, model, timeout (2m), allowInvalidCerts, temperature (0.7, 0..1), modelType: AiModelType (Chat\|Text, default Chat)}` + inherited `httpAuth: HttpAuth`, `httpHeaders`. New: `AiModel` is a group keyed on `@type`: `OpenAi@AiModelOpenAi`, `Anthropic@AiModelAnthropic`, `Gemini@AiModelGemini`, `Ollama@AiModelOllama`, `TypeSafe@AiModelTypeSafe`. Common (`AiModelCommon`): `name`, `model`, `url: Uri\|null` (label "Endpoint URL" -> "Base URL"), `apiKey: SecretKeyOptional`, `httpHeaders`, `allowInvalidCerts`, `timeout` (default 2m -> 1m), `maxConcurrentRequests` (16, 1..4096), `rateLimit: Rate\|null`. Generative providers (`AiModelGenerative`, all but `TypeSafe`): `maxOutputTokens` (4096), `temperature: Float\|null` (0..2, no default), `reasoning: AiReasoning` (Default), `extraParameters: Text\|null`. `AiModelOpenAi`: `profile: AiOpenAiProfile` (OpenAi\|Azure\|Vllm\|LlamaCpp\|Generic), `logprobs`. `AiModelGemini`: `logprobs`. `AiModelOllama`: `logprobs`, `keepAlive: Duration\|null`. Removed: `modelType`, `httpAuth` (Basic/Bearer group), the `HttpRequestHeaders` parent (only `httpHeaders` remains). `AiModelType` enum removed. | structure [C]; mapping of old object to `OpenAi` [L] |
| `SenderAuth.dkimSignDomain` -> `MtaStageData.dkimSignDomain` | Same type `Expression`, same default expression, same `expr-vars:MtaRcptToVariable`; moved with form section "DKIM Signing" | [C] |
| Task types `IndexDocument`, `UnindexDocument`, `IndexTrace` removed (+ subobjects `TaskIndexDocument{documentType: IndexDocumentType}`, `TaskIndexTrace{traceId: @Trace}`, enum `IndexDocumentType`) | Indexing work moved to an internal search index queue; `IndexQueueStatus` is only a read-only status view over the queue partitions, not a replacement object. New enum `IndexType` (5 variants, `telemetry` (E)). Permissions `taskIndexDocument`, `taskUnindexDocument`, `taskIndexTrace` removed. Pending index tasks are dropped; v1 rebuilds the index. | removal [C] |
| `Cache.dnsRbl` -> `Cache.spamLookup` | Same type `Size`; default "5mb" -> "6mb"; description widened ("DNSBL results" -> "DNSBL results and resolved URL redirects") | [C] |
| Telemetry events `Store.CacheMiss/CacheHit/CacheStale/CacheUpdate/CacheEntryTooLarge` -> `Cache.Miss/Hit/Stale/Update/EntryTooLarge` | New `Cache` event category; see section 6 | [C] (mapping file) |
| Metric `MessageIngest.IndexTime` -> `SearchIndex.IndexTime` | Same `id:1`, unit milliseconds | [C] |
| `WebHook` base `TracerCommon` -> `TracingEventSelection` | Effective field set unchanged (see 1.5) | [C] |

### 2.4 New sub-objects and enums (no standalone registry id)

- Authentication / OAuth: `OAuthClientKind` {registered, dynamic, metadataDocument, firstParty}, `OAuthClientMetadataPolicy` {disabled, sameDomain, any}, `OAuthScope` {mail, contacts, calendars, files}, `OAuthGrantType` {authorizationCode, refreshToken, deviceCode}.
- OIDC directory: `OidcOpaqueTokenValidation` {none, userInfo, introspection}, `OidcIntrospectionAuth` {clientSecretBasic, clientSecretPost, none}, `OidcUnscopedTokenPolicy` {reject, interoperable, full}.
- Azure blob store: group `AzureAuth` {`SharedKey@AzureAuthSharedKey{accountKey}`, `SasToken@AzureAuthSasToken{sasToken}`, `ClientSecret@AzureAuthClientSecret{tenantId, clientId, clientSecret}`, `ManagedIdentity@AzureAuthManagedIdentity{clientId: String\|null}`, `WorkloadIdentity@AzureAuthWorkloadIdentity{tenantId, clientId, tokenFile}`}; `AzureStore.environment` reuses the existing enum `AzureEnvironment` (already defined in v0.16).
- Cache swap: group `CacheSwap` {`Disabled`, `LocalFile@LocalFileSwap{path}`, `Redis@RedisSwap{store: RedisSwapStore, chunkSize 1mb, retention 7d}`, `BlobStore@BlobStoreSwap{store: BlobSwapStore, retention 7d}`}; base `CacheSwapBase{flushChanges 2000, flushInterval "10m", maxAccountSize "1gb", minAccountSize "1mb"}`; `RedisSwapStore` (group `Default`), `BlobSwapStore` (group `Default`).
- HTTP: `ClientIpSource` {peer, xForwardedFor, forwarded}.
- Metadata: `MetadataDataType` {Email, Mailbox, SieveScript, Calendar, CalendarEvent, AddressBook, ContactCard, FileNode}.
- Tasks: `ReloadSettingsResult{warnings: String[]}` (payload of `Action.ReloadSettings`, was payload-less `ReloadSettings@`), `TaskShareRevokeCleanup{objectType: SharedObjectType}` + `SharedObjectType` {mailbox, calendar, addressBook, fileNode}, `TaskReportWindow{windowEnd: UTCDateTime server-set, status: TaskStatus, due: UTCDateTime|null server-set}` (payload of the new `DmarcReportWindow` and `TlsReportWindow` tasks, which create the outgoing aggregate reports when their window ends), `IndexType`, `IndexStatus`, `IndexStatusFailed`.
- AI: `AiModelCommon`, `AiModelGenerative`, `AiModelOpenAi`, `AiModelAnthropic`, `AiModelGemini`, `AiModelOllama`, `AiModelTypeSafe`, `AiReasoning` {Default, Off, Low, Medium, High}, `AiOpenAiProfile` {OpenAi, Azure, Vllm, LlamaCpp, Generic}.
- Spam AI: `SpamAiTier`, `SpamAiCategory`, `SpamAiSignal`, `SpamAiMode` {Automatic, Shadow}, `SpamAiLearn`, `SpamAiLearnProperties`, `SpamAiWebSearch`, `SpamAiVariable` (expression variables `spam_score`, `spam_threshold`).
- DKIM2: `Dkim2HashAlgorithm` {sha256, sha512}.

### 2.5 Removed sub-objects and enums

`AiModelType` {Chat, Text}, `IndexDocumentType` (4 variants), `MtaRequireConstant` {optional, require, disable}, `MtaIpStrategyConstant` {ipv4_only, ipv6_only, ipv6_then_ipv4, ipv4_then_ipv6} (the last two were defined but referenced by no field in v0.16), `SearchTracingField` {eventType, queueId, keywords}, `SpamLlm`, `SpamLlmProperties`, `TaskIndexDocument`, `TaskIndexTrace`.

## 3. Field-level changes

### 3.1 Renamed fields (old -> new)

All identical in type and default unless the last column says otherwise.

| Object | Old | New | Type | Conf. | Note |
|---|---|---|---|---|---|
| Application | autoUpdateFrequency | autoUpdateInterval | Duration | C |  |
| Application | enabled | enable | Boolean | C |  |
| ArchivedSieveScript | content | contents | String | C |  |
| AsnResource | expires | refreshInterval | Duration | C | renamed via the intermediate name `refresh` during v1 development |
| Authentication | passwordMaxLength | maxPasswordLength | UnsignedInt | C |  |
| Authentication | passwordMinLength | minPasswordLength | UnsignedInt | C |  |
| Authentication | passwordMinStrength | minPasswordStrength | PasswordStrength | C |  |
| Bootstrap | serverHostname | defaultHostname | String | C |  |
| Cache | dnsRbl | spamLookup | Size | C | default 5mb -> 6mb; scope widened to URL redirect lookups |
| CalendarAlarm | fromEmail | fromAddress | EmailAddress\|null | C |  |
| CalendarScheduling | itipMaxSize | maxItipSize | Size | C |  |
| DmarcReport | dateRangeBegin | dateRangeStart | UTCDateTime | C |  |
| DmarcReportSettings | aggregateMaxReportSize | maxAggregateReportSize | Expression | C |  |
| DmarcTroubleshoot | to | rcptTo | EmailAddress[] | C |  |
| DnsResolverCommon | concurrency | maxConcurrentRequests | UnsignedInt | C |  |
| DnsServerAlidns | accessKey | accessKeyId | String | C |  |
| DnsServerAlidns | securityToken | sessionToken | SecretKeyOptional | C |  |
| DnsServerBaiduCloud | accessKey | accessKeyId | String | C |  |
| DnsServerBluecatV2 | baseUrl | url | String -> Uri | C |  |
| DnsServerCommon | pollingInterval | pollInterval | Duration | C |  |
| DnsServerConstellix | apiKey | apiKeyId | String | C |  |
| DnsServerCpanel | baseUrl | url | String -> Uri | C |  |
| DnsServerDnsMadeEasy | apiKey | apiKeyId | String | C |  |
| DnsServerDnsimple | authToken | token | SecretKey | C |  |
| DnsServerDomeneshop | authToken | token | String | C |  |
| DnsServerExoscale | apiKey | apiKeyId | String | C |  |
| DnsServerGlesys | apiUser | username | String | C |  |
| DnsServerGodaddy | apiKey | apiKeyId | String | C |  |
| DnsServerHuaweiCloud | accessKey | accessKeyId | String | C |  |
| DnsServerLightsail | secretAccessKey | secretKey | SecretKey | C |  |
| DnsServerLuaDns | authToken | token | SecretKey | C |  |
| DnsServerNameDotCom | authToken | token | SecretKey | C |  |
| DnsServerNetcup | apiKey | apiKeyId | String | C |  |
| DnsServerNifcloud | accessKey | accessKeyId | String | C |  |
| DnsServerPlesk | baseUrl | url | String -> Uri | C |  |
| DnsServerPorkbun | apiKey | apiKeyId | String | C |  |
| DnsServerPorkbun | secretApiKey | secret | SecretKey | C | the name of the old retired `secret` field (deprecated in v0.16) is reused for the live field |
| DnsServerPowerDns | endpoint | url | String\|null -> Uri\|null | C |  |
| DnsServerRoute53 | secretAccessKey | secretKey | SecretKey | C |  |
| DnsServerSpaceship | apiKey | apiKeyId | String | C |  |
| DnsServerTencentCloud | secretId | accessKeyId | String | C |  |
| DnsServerUltraDns | endpoint | url | String\|null -> Uri\|null | C |  |
| DnsServerVercel | authToken | token | SecretKey | C |  |
| DnsServerVolcengine | accessKey | accessKeyId | String | C |  |
| DnsServerWebSupport | apiKey | apiKeyId | String | C |  |
| Domain | isEnabled | enable | Boolean | C |  |
| EmailAlias | enabled | enable | Boolean | C |  |
| Enterprise | logoUrl | logo | Uri\|null -> String\|null | L | type Uri\|null -> String\|null; v1 accepts a URL or a base64-encoded image |
| HttpLookup | refresh | refreshInterval | Duration | C |  |
| Imap | maxConcurrent | maxConcurrentConnections | UnsignedInt\|null | C |  |
| Imap | maxRequestRate | rateLimit | Rate\|null | C |  |
| Imap | timeoutAnonymous | anonymousTimeout | Duration | C |  |
| Imap | timeoutAuthenticated | authenticatedTimeout | Duration | C |  |
| Imap | timeoutIdle | idleTimeout | Duration | C |  |
| Jmap | changesMaxResults | maxChangesResults | UnsignedInt | C |  |
| Jmap | getMaxResults | maxGetResults | UnsignedInt | C |  |
| Jmap | pushMaxAttempts | maxPushAttempts | UnsignedInt | C |  |
| Jmap | queryMaxResults | maxQueryResults | UnsignedInt | C |  |
| Jmap | setMaxObjects | maxSetObjects | UnsignedInt | C |  |
| Jmap | snippetMaxResults | maxSnippetResults | UnsignedInt | C |  |
| KafkaCoordinator | brokers | hosts | String[] | C |  |
| KafkaCoordinator | timeoutMessage | messageTimeout | Duration | C |  |
| KafkaCoordinator | timeoutSession | sessionTimeout | Duration | C |  |
| LdapDirectory | filterMailbox | filterRecipient | String | C |  |
| MaskedEmail | enabled | enable | Boolean | C |  |
| MeilisearchStore | maxRetries | maxPolls | UnsignedInt | L | description "Number of times to poll for task status" -> "Maximum number of task status polls" |
| MetricsOtelGrpc | endpoint | url | Uri\|null | C |  |
| MetricsOtelHttp | endpoint | url | Uri | C |  |
| MtaConnectionIpHost | sourceIp | localIp | IpAddr | C |  |
| MtaConnectionStrategy | sourceIps | localIps | MtaConnectionIpHost[] | C |  |
| MtaInboundSession | timeout | idleTimeout | Expression | C |  |
| MtaMilter | hostname | host | String | C |  |
| MtaMilter | timeoutCommand | commandTimeout | Duration | C |  |
| MtaMilter | timeoutConnect | connectTimeout | Duration | C |  |
| MtaMilter | timeoutData | dataTimeout | Duration | C |  |
| MtaRouteRelay | address | host | String | C |  |
| MySqlStore | timeout | idleTimeout | Duration\|null | C | only the description changed: both versions pass the value to MySQL `wait_timeout`, default 15000 ms in both |
| NatsCoordinator | addresses | hosts | String[] | C | default changed 127.0.0.1:4444 -> 127.0.0.1:4222 |
| NatsCoordinator | capacityClient | clientCapacity | UnsignedInt | C |  |
| NatsCoordinator | capacityReadBuffer | readBufferCapacity | UnsignedInt | C |  |
| NatsCoordinator | capacitySubscription | subscriptionCapacity | UnsignedInt | C |  |
| NatsCoordinator | timeoutConnection | connectTimeout | Duration | C |  |
| NatsCoordinator | timeoutRequest | requestTimeout | Duration | C |  |
| NetworkListener | tlsImplicit | implicitTls | Boolean | C |  |
| OidcDirectory | requireAudience | acceptedAudiences | String\|null -> String[] | L | type String\|null -> String[]; single value becomes one-element list |
| PasswordCredential | otpAuth | otpUrl | Uri\|null | C |  |
| PostgreSqlStore | timeout | connectTimeout | Duration\|null | C |  |
| RedisClusterStore | timeout | connectTimeout | Duration | C |  |
| RedisSentinelStore | timeout | connectTimeout | Duration | C |  |
| RedisStore | timeout | connectTimeout | Duration | C |  |
| ReportSettings | inboundReportMaxSize | maxInboundReportSize | Integer -> Size | C | type Integer -> Size (same numeric default 26214400, min 1024) |
| S3Store | accessKey | accessKeyId | PublicStringOptional | C |  |
| S3StoreCustomRegion | customEndpoint | url | Uri | C |  |
| S3StoreCustomRegion | customRegion | region | String | C |  |
| SpamClassifier | trainFrequency | trainInterval | Duration\|null | C |  |
| SpamClassify | envFrom | mailFrom | EmailAddress | C |  |
| SpamClassify | envFromParameters | mailFromParameters | SpamClassifyParameters\|null | C |  |
| SpamClassify | envRcptTo | rcptTo | EmailAddress[] | C |  |
| TracerOtelGrpc | endpoint | url | Uri\|null | C |  |
| TracerOtelHttp | endpoint | url | Uri | C |  |
| WebDav | livePropertyMaxSize | maxLivePropertySize | Size | C |  |
| WebDav | requestMaxSize | maxRequestSize | Size | C |  |

Pattern notes: the DNS provider key renames apply to the matching `DnsServer*` group payload; `DnsServerCommon.pollInterval` applies to every provider. `S3StoreCustomRegion` is the payload of the `Custom@S3StoreCustomRegion` variant of the S3 region group.

### 3.2 Restructured fields (not simple renames)

| Object | v0.16 | v1 | Conf. |
|---|---|---|---|
| `AzureStore` | `accessKey: SecretKeyOptional`, `sasToken: SecretKeyOptional` | `auth: AzureAuth` group: `SharedKey{accountKey}`, `SasToken{sasToken}`, `ClientSecret{tenantId, clientId, clientSecret}`, `ManagedIdentity{clientId}`, `WorkloadIdentity{tenantId, clientId, tokenFile}`; plus `environment`, `url`. `maxRetries` min-value 1 -> 0 | L |
| `Http` | `useXForwarded: Boolean` (false) | `clientIpSource: ClientIpSource` (`peer`), `forwardedHops: UnsignedInt` (1, 1..16) | L |
| `S3Store` | `accessKey`, `securityToken`, `sessionToken` | `accessKeyId`, `sessionToken`; `securityToken` removed (fold into `sessionToken` when that is empty); `maxRetries` min-value 1 -> 0 | C / L |
| `OidcDirectory` | `requireAudience: String\|null`, `requireScopes: String[]` (default `["openid","email"]`), `claimName` default `"name"` | `acceptedAudiences: String[]`; `requireScopes` removed; `claimName` default removed (null); new `allowInvalidCerts`, `opaqueTokenValidation`, `introspection*`, `unscopedTokens`, `skipAudienceValidation`, `allowIdTokenClaims`, `lenientIssuerMatch` | L / removed |
| `OidcProvider` | `authCodeMaxAttempts`, `anonymousClientRegistration`, `requireClientRegistration`, `refreshTokenRenewal` | all removed; `clientMetadataDocuments: OAuthClientMetadataPolicy` added; `authCodeExpiry`, `accessTokenExpiry` min 600000 ms, `refreshTokenExpiry` min 86400000 ms | removed |
| `OAuthClient` | `memberTenantId` (not gated) | + `postLogoutRedirectUris`, `firstParty`, `scopes: OAuthScope[]`, `grantTypes: OAuthGrantType[]`; `memberTenantId` enterprise | added |
| `LdapDirectory` | `filterMailbox` | `filterRecipient` (same default), + `urlFailover: Uri[]` (E) | C |
| `Search` | `indexTracingFields: SearchTracingField[]` (E); `indexEmailFields`/`indexCalendarFields`/`indexContactFields` could contain `receivedAt, sentAt, size, hasAttachment` / `start, uid` / `uid` | `indexTracingFields` removed; those variants removed from the three enums (defaults shortened accordingly) | removed |
| `AcmeProvider` | `description`: `server-set`, `no-store`, `hide:ui` (computed, not stored) | `description`: stored, trimmed, text-indexed (`index-text-as-text`); new server-set `accountHashPrefix: Uri\|null`, `issuerDomainNames: String[]`, `caaIdentities: String[]` | C |
| `Enterprise` | `logoUrl: Uri\|null` (E, trim) | `logo: String\|null` (E): URL or base64 image | L |
| `Metric` (packed) | no node | + `nodeId: UnsignedInt` (0) via `MetricBase` (and filter/column in `Metric` list) | added |
| Report settings | expressions use `system('domain')` | defaults use `system('report_domain')`; `outboundReportDomain` form label "Default Domain" -> "Report Domain" (see 3.6) | C |

### 3.3 Added fields

Fields added to objects that existed in v0.16 (new objects are in 2.1). Renamed targets and fields that only moved to a parent are excluded.

| Object | Field | Type / default / flags | Note |
|---|---|---|---|
| AcmeProvider | accountHashPrefix | `Uri\|null`, server-set |  |
| AcmeProvider | issuerDomainNames | `String[]`, server-set |  |
| AcmeProvider | caaIdentities | `String[]`, server-set |  |
| AddressBook | maxAddressBooksPerCard | `UnsignedInt`, default `10`, min-value:1 |  |
| AddressBook | maxMediaSize | `Size`, default `"2mb"` |  |
| AzureStore | environment | `AzureEnvironment`, default `"public"` |  |
| AzureStore | url | `Uri\|null` | blob service URL override |
| AzureStore | auth | `AzureAuth` | group `AzureAuth`; carries former `accessKey`/`sasToken` (see 3.2) |
| Cache | messagesLarge | `Size`, default `"512mb"` |  |
| Cache | messagesLargeTtl | `Duration`, default `"1h"` |  |
| Cache | groupwareLarge | `Size`, default `"512mb"` |  |
| Cache | groupwareLargeTtl | `Duration`, default `"1h"` |  |
| Cache | directoryRecipients | `Size`, default `"2mb"`, min-value:2048 |  |
| Cache | directoryRecipientsTtl | `Duration`, default `"10m"` |  |
| Cache | swap | `CacheSwap` |  |
| Calendar | maxCalendarsPerEvent | `UnsignedInt`, default `10`, min-value:1 |  |
| Calendar | maxExpandedQueryDuration | `Duration`, default `"365d"` |  |
| Calendar | maxAvailabilityDuration | `Duration`, default `"365d"` |  |
| Calendar | availabilityRateLimit | `Rate\|null`, default `{"count": 100, "period": "1m"}` |  |
| Calendar | maxAttachmentsSize | `Size`, default `"5mb"` |  |
| Dkim2Signature | instanceHashes | `Dkim2HashAlgorithm[]`, default `["sha256"]`, min-items:1 |  |
| Email | maxMailboxesPerEmail | `UnsignedInt`, default `100`, min-value:1 |  |
| Email | maxFlagsPerEmail | `UnsignedInt`, default `100`, min-value:1 |  |
| Email | maxFlagLength | `UnsignedInt`, default `128`, min-value:1, max-value:1024 |  |
| Email | maxHeaderSize | `Size`, default `524288`, min-value:1024 |  |
| Email | maxHeaderCount | `UnsignedInt`, default `5000`, min-value:100 |  |
| Http | clientIpSource | `ClientIpSource`, default `"peer"` | replaces `useXForwarded` (see 3.2) |
| Http | forwardedHops | `UnsignedInt`, default `1`, min-value:1, max-value:16 |  |
| KafkaCoordinator | useTls | `Boolean`, default `false` |  |
| KafkaCoordinator | allowInvalidCerts | `Boolean`, default `false` |  |
| LdapDirectory | urlFailover | `Uri[]`, enterprise | secondary directory servers |
| MetricBase | nodeId | `UnsignedInt`, default `0` | on `Metric` (packed); also in list filters |
| NatsCoordinator | allowInvalidCerts | `Boolean`, default `false` |  |
| OAuthClient | postLogoutRedirectUris | `Uri[]` |  |
| OAuthClient | firstParty | `Boolean`, default `false` |  |
| OAuthClient | scopes | `OAuthScope[]` |  |
| OAuthClient | grantTypes | `OAuthGrantType[]`, default `["authorizationCode","refreshToken"]` |  |
| OidcDirectory | allowInvalidCerts | `Boolean`, default `false` |  |
| OidcDirectory | opaqueTokenValidation | `OidcOpaqueTokenValidation`, default `"none"` |  |
| OidcDirectory | introspectionClientId | `String\|null` |  |
| OidcDirectory | introspectionClientSecret | `SecretKeyOptional` |  |
| OidcDirectory | introspectionAuthMethod | `OidcIntrospectionAuth`, default `"clientSecretBasic"` |  |
| OidcDirectory | unscopedTokens | `OidcUnscopedTokenPolicy`, default `"reject"` |  |
| OidcDirectory | skipAudienceValidation | `Boolean`, default `false` |  |
| OidcDirectory | allowIdTokenClaims | `Boolean`, default `false` |  |
| OidcDirectory | lenientIssuerMatch | `Boolean`, default `false` |  |
| OidcProvider | clientMetadataDocuments | `OAuthClientMetadataPolicy`, default `"disabled"` |  |
| RedisClusterStore | allowInvalidCerts | `Boolean`, default `false` |  |
| RedisSentinelStore | allowInvalidCerts | `Boolean`, default `false` |  |
| RedisStore | allowInvalidCerts | `Boolean`, default `false` |  |
| Search | maxConcurrentIndexTasks | `UnsignedInt`, default `5`, min-value:1 |  |
| Search | indexFiles | `Boolean`, default `true` |  |
| Search | maxExtractDocumentSize | `Size`, default `67108864`, min-value:1 |  |
| Search | maxExtractTextSize | `Size`, default `4194304`, min-value:1 |  |
| Search | maxExtractDecompressedSize | `Size`, default `268435456`, min-value:1 |  |
| Search | maxExtractPartSize | `Size`, default `67108864`, min-value:1 |  |
| Search | maxExtractParts | `UnsignedInt`, default `10000`, min-value:1 |  |
| Search | maxExtractArchiveEntries | `UnsignedInt`, default `10000`, min-value:1 |  |
| Search | maxExtractPdfObjects | `UnsignedInt`, default `1048576`, min-value:1 |  |
| Search | maxExtractRtfDepth | `UnsignedInt`, default `256`, min-value:1 |  |
| SpamClassify | aiGate | `String\|null`, server-set, enterprise |  |
| SpamClassify | aiFacts | `Text\|null`, server-set, enterprise |  |
| SpamClassify | aiVerdict | `String\|null`, server-set, enterprise |  |
| SpamSettings | maxBodyText | `Size`, default `262144`, min-value:1024, max-value:16777216 |  |
| SpamSettings | maxAttachmentText | `Size`, default `65536`, min-value:1024, max-value:16777216 |  |
| SpamSettings | maxMessageText | `Size`, default `1048576`, min-value:1024, max-value:67108864 |  |
| SpamSettings | maxRedirectUrls | `UnsignedInt`, default `10`, max-value:1000, min-value:0 |  |
| SpamSettings | redirectTimeout | `Duration`, default `"5s"` |  |
| SpamSettings | redirectCacheTtl | `Duration`, default `"1d"` |  |
| SystemSettings | maxBufferedMemory | `Size\|null`, min-value:16777216 |  |
| SystemSettings | includeSecrets | `Boolean`, default `false` |  |
| TaskCalendarAlarmEmail | targetAccountId | `@Account\|null`, server-set |  |
| TaskCalendarAlarmEmail | recurrenceId | `Integer\|null`, server-set |  |
| TaskCalendarAlarmNotification | targetAccountId | `@Account\|null`, server-set |  |
| TaskDestroyAccount | memberGroupIds | `@Account[]`, server-set |  |
| TracerOtelHttp | allowInvalidCerts | `Boolean`, default `false` |  |
| TaskManager | alertAfter | `UnsignedInt`, default `5`, min-value:1 | Tasks redesign |

`WebHook.enable/level/lossy` and `MtaStageData.dkimSignDomain` are moves, not additions (see 1.5, 2.3).

### 3.4 Removed fields

Fields of objects that still exist in v1. Fields that only moved to a parent class (`HttpLookup.timeout`, `MtaHook.timeout/allowInvalidCerts`, `WebHook.timeout/allowInvalidCerts`) are not listed (see 1.5).

| Object | Field | Old type / default | Equivalent / note |
|---|---|---|---|
| AcmeProvider | maxRetries | `Integer`, default `10` | no equivalent (ACME retries are handled internally) |
| AiModel | name | `String` | moved to `AiModelCommon.name` |
| AiModel | allowInvalidCerts | `Boolean`, default `false` | moved to `AiModelCommon.allowInvalidCerts` |
| AiModel | temperature | `Float`, default `0.7`, max-value:1, min-value:0 | moved to `AiModelGenerative.temperature` (now `Float\|null`, 0..2, no default; absent on `TypeSafe`) |
| AiModel | model | `String` | moved to `AiModelCommon.model` |
| AiModel | timeout | `Duration`, default `"2m"` | moved to `AiModelCommon.timeout` (default 2m -> 1m) |
| AiModel | modelType | `AiModelType`, default `"Chat"` | no equivalent (Chat\|Text selector gone) |
| AiModel | url | `Uri` | moved to `AiModelCommon.url` (now `Uri\|null`) |
| AzureStore | accessKey | `SecretKeyOptional` | -> `auth` = `SharedKey{accountKey}` [L] |
| AzureStore | sasToken | `SecretKeyOptional` | -> `auth` = `SasToken{sasToken}` [L] |
| DmarcReportSettings | aggregateSubject | `Expression`, default `"'DMARC Aggregate Report'"` | no equivalent (aggregate report subject no longer configurable) |
| DnsServerCloudflare | email | `String\|null` | retired stored field in v0.16 (deprecated, `no-store`) |
| DnsServerDnsimple | secret | `SecretKey` | retired stored field in v0.16 (deprecated); live field is `token` |
| Http | useXForwarded | `Boolean`, default `false` | -> `clientIpSource` (+ `forwardedHops`); false -> `peer`; true -> `forwarded` or `xForwardedFor` [L]; v0.16 reads the `Forwarded` header |
| OidcDirectory | requireScopes | `String[]`, default `["openid","email"]` | no equivalent field (default was `["openid","email"]`) |
| OidcProvider | authCodeMaxAttempts | `UnsignedInt`, default `3`, min-value:1, max-value:1000 | no equivalent |
| OidcProvider | anonymousClientRegistration | `Boolean`, default `true` | no equivalent; permissions `oAuthClientRegistration`, `oAuthClientOverride` removed too. v1 always accepts RFC 7591 registration of public clients under the anonymous HTTP rate limit and requires `sysOAuthClientCreate` for confidential clients; `clientMetadataDocuments` governs only Client ID Metadata Documents, it is not a replacement |
| OidcProvider | requireClientRegistration | `Boolean`, default `false` | no equivalent (see `anonymousClientRegistration`) |
| OidcProvider | refreshTokenRenewal | `Duration`, default `"4d"` | no equivalent; `refreshTokenExpiry` relabelled "Refresh token idle timeout" and gained `min-value:86400000` |
| S3Store | securityToken | `SecretKeyOptional` | `sessionToken` already existed in v0.16 next to it and is kept; `securityToken` was a duplicate [L] (the v1 migration maps `session-token`, falling back to `security-token`, to `sessionToken`) |
| Search | indexTracingFields | `SearchTracingField[]`, default `["eventType","queueId","keywords"]`, enterprise | no equivalent (enum `SearchTracingField` removed; `IndexType` gained `telemetry` (E), relation unverified) |
| SieveSystemInterpreter | duplicateExpiry | `Duration`, default `"7d"` | no equivalent |
| SystemSettings | threadPoolSize | `UnsignedInt\|null`, min-value:1 | no equivalent (thread pool removed) |
| TaskManager | maxAttempts | `UnsignedInt`, default `3`, min-value:1 | no equivalent: v1 retries transient failures indefinitely and reports a task as stalled after `alertAfter` (default 5) attempts (Tasks redesign) |
| TaskManager | totalDeadline | `Duration`, default `"6h"` | no equivalent: permanently failed tasks stay until an operator acts on them (Tasks redesign) |
| TlsReportSettings | subject | `Expression`, default `"'TLS Aggregate Report'"` | no equivalent (TLS report subject no longer configurable) |
| WebDav | deadPropertyMaxSize | `Size\|null`, default `1024` | no equivalent |

### 3.5 Type changes

Includes renames whose type also changed.

| Object.field | Old type | New type | Note |
|---|---|---|---|
| DnsServerInfoblox.port | `String\|null` | `UnsignedInt\|null` | also `min-value:1`, `max-value:65535` |
| Jmap.maxUploadSize | `UnsignedInt` | `Size` | numeric value unchanged (bytes) |
| Jmap.maxPushSize | `UnsignedInt` | `Size` | numeric value unchanged (bytes) |
| RocksDbStore.cacheSize | `Size` | `Size\|null` | default 134217728 removed (null = engine default) |
| SieveSystemScript.contents | `Text` | `Sieve` | editor hint only (stored as String) |
| SieveUserScript.contents | `Text` | `Sieve` | editor hint only (stored as String) |
| SqliteStore.poolMaxConnections | `UnsignedInt` | `UnsignedInt\|null` | default 10 removed (null = automatic) |
| ReportSettings.inboundReportMaxSize | `Integer` | `Size` | renamed to `maxInboundReportSize` |
| DnsServerBluecatV2/Cpanel/Plesk.baseUrl | `String` | `Uri` | renamed to `url` |
| DnsServerPowerDns/UltraDns.endpoint | `String\|null` | `Uri\|null` | renamed to `url` |
| Enterprise.logoUrl | `Uri\|null` | `String\|null` | renamed to `logo` |
| OidcDirectory.requireAudience | `String\|null` | `String[]` | renamed to `acceptedAudiences` [L] |
| AiModel.url | `Uri` | `Uri\|null` | now on `AiModelCommon` |
| AiModel.temperature | `Float (0..1, default 0.7)` | `Float\|null (0..2, no default)` | now on `AiModelGenerative` |
| SpamLlmProperties.categories | `String[]` | `SpamAiCategory[]` | now `SpamAiProperties.categories` |

### 3.6 Default value changes

Defaults only (renames with a default change are in 3.1). `system('report_domain')` is a new `system()` key; the label of `ReportSettings.outboundReportDomain` changed "Default Domain" -> "Report Domain".

| Object.field | Old default | New default |
|---|---|---|
| Cache.contacts | `"10mb"` | `"32mb"` |
| Cache.dnsIpv4 | `"5mb"` | `"2mb"` |
| Cache.dnsIpv6 | `"5mb"` | `"1mb"` |
| Cache.dnsMx | `"5mb"` | `"2mb"` |
| Cache.dnsTxt | `"5mb"` | `"8mb"` |
| Cache.events | `"10mb"` | `"48mb"` |
| Cache.scheduling | `"1mb"` | `"6mb"` |
| Cache.files | `"10mb"` | `"24mb"` |
| Cache.httpAuth | `"1mb"` | `"2mb"` |
| Cache.messages | `"50mb"` | `"320mb"` |
| Cache.domains | `"5mb"` | `"2mb"` |
| Cache.domainNames | `"10mb"` | `"1mb"` |
| Cache.domainNamesNegative | `"1mb"` | `"2mb"` |
| Cache.emailAddresses | `"10mb"` | `"8mb"` |
| Cache.accounts | `"20mb"` | `"16mb"` |
| Cache.roles | `"5mb"` | `"1mb"` |
| Cache.tenants | `"5mb"` | `"1mb"` |
| Cache.dkimSignatures | `"10mb"` | `"8mb"` |
| DkimReportSettings.fromAddress | `"'noreply-dkim@' + system('domain')"` | `"'noreply-dkim@' + system('report_domain')"` |
| DkimReportSettings.dkimSignDomain | `"system('domain')"` | `"system('report_domain')"` |
| DmarcReportSettings.aggregateFromAddress | `"'noreply-dmarc@' + system('domain')"` | `"'noreply-dmarc@' + system('report_domain')"` |
| DmarcReportSettings.aggregateOrgName | `"system('domain')"` | `"system('report_domain')"` |
| DmarcReportSettings.aggregateDkimSignDomain | `"system('domain')"` | `"system('report_domain')"` |
| DmarcReportSettings.failureFromAddress | `"'noreply-dmarc@' + system('domain')"` | `"'noreply-dmarc@' + system('report_domain')"` |
| DmarcReportSettings.failureDkimSignDomain | `"system('domain')"` | `"system('report_domain')"` |
| Domain.dkimManagement | `(no explicit default)` | `{"@type":"Automatic"}` |
| DsnReportSettings.fromAddress | `"'MAILER-DAEMON@' + system('domain')"` | `"'MAILER-DAEMON@' + system('report_domain')"` |
| DsnReportSettings.dkimSignDomain | `"system('domain')"` | `"system('report_domain')"` |
| MtaStageAuth.saslMechanisms | `{"else":"false","match":[{"if":"local_port != 25 && is_tls","then":"[plain, login, oauthbearer, xoauth2]"},...` | `{"else":"false","match":[{"if":"local_port != 25 && is_tls","then":"[plain, login, oauthbearer, xoauth2]"}]}` |
| MySqlStore.poolMaxConnections | `10` | `(none)` |
| NetworkListener.maxConnections | `8192` | `(none)` |
| OidcDirectory.claimName | `"name"` | `(none)` |
| PostgreSqlStore.poolMaxConnections | `10` | `(none)` |
| RedisClusterStore.authUsername | `"stalwart"` | `(none)` |
| RedisSentinelStore.authUsername | `"stalwart"` | `(none)` |
| RocksDbStore.blobSize | `16834` | `4096` |
| RocksDbStore.cacheSize | `134217728` | `(none)` |
| Search.indexCalendarFields | `["title","description","location","owner","attendee","start","uid"]` | `["title","description","location","owner","attendee"]` |
| Search.indexContactFields | `["member","kind","name","nickname","organization","email","phone","onlineService","address","note","uid"]` | `["member","kind","name","nickname","organization","email","phone","onlineService","address","note"]` |
| Search.indexEmailFields | `["from","to","cc","bcc","subject","body","attachment","receivedAt","sentAt","size","hasAttachment"]` | `["from","to","cc","bcc","subject","body","attachment"]` |
| SpamPyzor.enable | `true` | `false` |
| SpfReportSettings.fromAddress | `"'noreply-spf@' + system('domain')"` | `"'noreply-spf@' + system('report_domain')"` |
| SpfReportSettings.dkimSignDomain | `"system('domain')"` | `"system('report_domain')"` |
| SqlDirectory.queryLogin | `"SELECT name, secret, description, type FROM accounts WHERE name = $1"` | `"SELECT name, secret, description, type FROM accounts WHERE name = $1 AND active = true"` |
| SqliteStore.poolMaxConnections | `10` | `(none)` |
| TlsReportSettings.fromAddress | `"'noreply-tls@' + system('domain')"` | `"'noreply-tls@' + system('report_domain')"` |
| TlsReportSettings.orgName | `"system('domain')"` | `"system('report_domain')"` |
| TlsReportSettings.dkimSignDomain | `"system('domain')"` | `"system('report_domain')"` |
| TracerLog.prefix | `"stalwart"` | `"stalwart.log"` |
| TaskRetryStrategyBackoff.maxDelay | `"30m"` | `"6h"` |

Also changed without a schema-visible default: `NetworkListener.maxConnections` and the pool sizes above lose their numeric default (field is nullable, null = automatic) [L]; `InMemoryStore.Default@` label "Use data store" -> "Local in-process store (single node only)" (same variant position 0, different meaning for deployments relying on the default); `Domain.dkimManagement` gained an explicit default group `Automatic`; `TracerLog.prefix` default `stalwart` -> `stalwart.log`; `MtaStageAuth.saslMechanisms` default drops the `local_port != 25 -> [oauthbearer, xoauth2]` branch.

### 3.7 Constraint, flag and expression-variable changes

| Object.field | Constraint | Old | New |
|---|---|---|---|
| AcmeProvider.description | server-set | `server-set` | `(none)` |
| AcmeProvider.description | index | `(none)` | `index-text-as-text` |
| AcmeProvider.description | hide | `hide:ui` | `(none)` |
| AcmeProvider.description | no-store | `no-store` | `(none)` |
| AzureStore.maxRetries | min-value | `min-value:1` | `min-value:0` |
| DmarcReportSettings.aggregateDkimSignDomain | expr-vars | `expr-vars:MtaRcptDomainVariable` | `expr-vars:MtaQueueSenderVariable` |
| DnsServerInfoblox.port | min-value | `(none)` | `min-value:1` |
| DnsServerInfoblox.port | max-value | `(none)` | `max-value:65535` |
| DnsServerPorkbun.secret | hide | `hide:ui` | `(none)` |
| DnsServerPorkbun.secret | no-store | `no-store` | `(none)` |
| MtaInboundThrottle.description | read-only | `read-only` | `(none)` |
| MtaQueueQuota.description | read-only | `read-only` | `(none)` |
| OidcProvider.authCodeExpiry | min-value | `(none)` | `min-value:600000` |
| OidcProvider.refreshTokenExpiry | min-value | `(none)` | `min-value:86400000` |
| OidcProvider.accessTokenExpiry | min-value | `(none)` | `min-value:600000` |
| S3Store.maxRetries | min-value | `min-value:1` | `min-value:0` |
| TlsReportSettings.contactInfo | expr-vars | `expr-vars:MtaQueueHostVariable` | `expr-vars:MtaRcptDomainVariable` |
| TlsReportSettings.fromAddress | expr-vars | `expr-vars:MtaQueueHostVariable` | `expr-vars:MtaRcptDomainVariable` |
| TlsReportSettings.fromName | expr-vars | `expr-vars:MtaQueueHostVariable` | `expr-vars:MtaRcptDomainVariable` |
| TlsReportSettings.maxReportSize | expr-vars | `expr-vars:MtaQueueHostVariable` | `expr-vars:MtaRcptDomainVariable` |
| TlsReportSettings.orgName | expr-vars | `expr-vars:MtaQueueHostVariable` | `expr-vars:MtaRcptDomainVariable` |
| TlsReportSettings.dkimSignDomain | expr-vars | `expr-vars:MtaQueueHostVariable` | `expr-vars:MtaQueueSenderVariable` |

Expression variable sets:

| Variable set | Removed | Added | Used by |
|---|---|---|---|
| `MtaQueueSenderVariable` | `retry_num`, `notify_num`, `expires_in`, `last_status`, `last_error` | `recipients` | `dkimSignDomain` of DMARC aggregate and TLS report settings (v0.16 used `MtaRcptDomainVariable` / `MtaQueueHostVariable`) |
| `SpamDefaultVariable` | none | `spam_probability` | all spam expressions |
| `SpamIpVariable` | `reverse_ip` | none | DNSBL expressions (`ip_reverse` remains) |
| `ExpressionVariable` (global enum) | `reverse_ip` | `spam_score`, `spam_probability`, `spam_threshold` | enum of known variable names |
| `SpamAiVariable` (new) | none | `spam_score`, `spam_threshold` (+ `SpamDefaultVariable`) | `SpamAiProperties.condition` |

Existing stored expressions that reference a variable outside the v1 context of their field are rejected when v1 compiles them ("Variable ... not allowed in this context"; an unknown word fails with "Invalid variable or constant"). Affected:

- `retry_num`, `notify_num`, `expires_in`, `last_status`, `last_error` in every `MtaQueueSenderVariable` field (DSN report settings, and the DKIM sign domain of DMARC aggregate and TLS reports).
- `DmarcReportSettings.aggregateDkimSignDomain`: `rcpt_domain` (v0.16 context `MtaRcptDomainVariable`, v1 `MtaQueueSenderVariable`).
- `TlsReportSettings.contactInfo/fromAddress/fromName/maxReportSize/orgName`: every `MtaQueueHostVariable` name except `rcpt_domain` (v1 context `MtaRcptDomainVariable`); `TlsReportSettings.dkimSignDomain`: the `MtaQueueHostVariable` names missing from v1 `MtaQueueSenderVariable` (`rcpt_domain`, `rcpt`, `mx`, `remote_ip`, `local_ip`, `retry_num`, ...).
- `SieveUserInterpreter.dkimSignDomain`: `retry_num`, `notify_num`, `expires_in`, `last_status`, `last_error` (the full list of reductions is in `mapping/expression_contexts.json` and enforced by the mapping completeness check).
- Functions: `counter_incr` and `counter_get` were removed. v1 has `key_incr` with the same arguments; there is no counter read, since `key_get` returns nothing for a counter entry, so `counter_get(store, key)` becomes `key_incr(store, key, 0)`, which returns the current value.
- `reverse_ip`: declared in v0.16 but never evaluated; removed from the v1 enum, so a v1 expression that uses it fails to compile. v1 evaluates `ip_reverse`. The mapping renames `reverse_ip` to `ip_reverse` inside expressions; the other cases are replaced by the v1 default (transform `expression_removed_vars`).

## 4. Enum and group variant changes

Positions are the stored discriminants (section 1.1). "Append" means no shift of existing variants.

| Enum / group | Change |
|---|---|
| `DnsServer` (group) | `Deprecated1@` (position 1) removed; every later variant shifts by -1 (71 -> 70 variants) |
| `DkimSignature` (group) | append `Dkim2MlDsa44Ed25519Sha512@Dkim2Signature` (position 4); `Dkim2Signature` gains `instanceHashes: Dkim2HashAlgorithm[]` (default `["sha256"]`) |
| `Task` (group) | remove `IndexDocument`, `UnindexDocument`, `IndexTrace` (positions 0-2); append `ShareRevokeCleanup@TaskShareRevokeCleanup`, `DmarcReportWindow@TaskReportWindow`, `TlsReportWindow@TaskReportWindow`; 18 -> 18 variants, all others shift by -3; `RestoreArchivedItem`, `TenantMaintenance` now enterprise |
| `Action` (group) | `ReloadSettings@` -> `ReloadSettings@ReloadSettingsResult` (same position) |
| `AiModel` (group) | new: `OpenAi`, `Anthropic`, `Gemini`, `Ollama`, `TypeSafe` (was a plain object) |
| `BlobStore`, `InMemoryStore`, `LookupStore` (groups) | `Sharded@...` now enterprise; `InMemoryStore.Default` relabelled (3.6) |
| `Dkim2Flag` | remove `donotmodify`, `donotexplode` (3 -> 1: only `feedback` left) |
| `ExpressionConstant` | remove `optional`, `require`, `ipv4_only`, `ipv6_only`, `ipv6_then_ipv4`, `ipv4_then_ipv6` (19 -> 13; no field referenced them) |
| `Locale` | remove the 14 `_reserved_*` placeholders (positions 70, 75, 86, 95, 103, 117, 136, 140, 144, 179, 234, 236, 253, 287); 336 -> 322; all locales after position 70 shift |
| `SearchEmailField` | remove `receivedAt`, `sentAt`, `size`, `hasAttachment` (12 -> 8) |
| `SearchCalendarField` | remove `start`, `uid` (7 -> 5) |
| `SearchContactField` | remove `uid` (11 -> 10) |
| `TaskStoreMaintenanceType` | remove `removeSieveId`; `reindexTelemetry`, `resetTenantQuotas` now enterprise (15 -> 14) |
| `TaskAccountMaintenanceType` | append `rebuildShares` |
| `StorageQuota` | variant `maxMaskedAddresses` now enterprise |
| `Key` (telemetry, stored in `Trace`) | append 30: `name`, `objectType`, `property`, `nodeId`, `remoteNodeId`, `taskId`, `partition`, `index`, `attempt`, `used`, `period`, `retryAfter`, `command`, `tag`, `address`, `ip`, `headers`, `query`, `cipher`, `resourceUid`, `script`, `model`, `inputTokens`, `outputTokens`, `cachedTokens`, `finishReason`, `category`, `probability`, `confidence`, `tier` (66 -> 96; first 66 unchanged, verified by prefix comparison) |
| `TraceValue` group `Duration@TraceValueDuration` | label "seconds" -> "milliseconds" (packed `Trace` data; unit changed) |

Other enum additions listed in 2.4 (`OAuth*`, `Oidc*`, `ClientIpSource`, `MetadataDataType`, `IndexType`, `SharedObjectType`, `AiReasoning`, `AiOpenAiProfile`, `SpamAiMode`, `Dkim2HashAlgorithm`).

## 5. Permissions

Declared (non-`sys*`) permissions and the per-object `sys*` permissions. 37 names removed, 19 added, 561 of 624 shared names changed numeric id.

Removed (37):
- Category `OAuth` deleted: `oAuthClientRegistration`, `oAuthClientOverride`.
- Category `JmapPrincipal`: `create`, `update`, `destroy` -> `jmapPrincipalCreate`, `jmapPrincipalUpdate`, `jmapPrincipalDestroy`.
- Object permissions dropped by `no-operations` (1.4): `sysActionGet/Update/Destroy/Query`, `sysArchivedItemCreate`, `sysArfExternalReportCreate/Update`, `sysClusterNodeCreate/Update/Destroy`, `sysDmarcExternalReportCreate/Update`, `sysDmarcInternalReportCreate`, `sysLogCreate/Update/Destroy`, `sysMetricCreate/Update/Destroy`, `sysQueuedMessageCreate`, `sysSpamTrainingSampleUpdate`, `sysTlsExternalReportCreate/Update`, `sysTlsInternalReportCreate`, `sysTraceCreate/Update/Destroy`.
- `sysSpamLlmGet`, `sysSpamLlmUpdate` (object renamed: now `sysSpamAiGet`, `sysSpamAiUpdate`) [C].
- Task permissions: `taskIndexDocument`, `taskUnindexDocument`, `taskIndexTrace`.

Added (19): `imapMetadataGet`, `imapMetadataSet`, `imapMetadataPrivate`, `jmapMetadataGet`, `jmapMetadataSet`, `jmapMetadataPrivate` (new categories `ImapMetadata`, `JmapMetadata`), `sysMetadataGet`, `sysMetadataUpdate`, `sysSpamAiGet`, `sysSpamAiUpdate`, `sysOAuthGrantGet`, `sysOAuthGrantQuery`, `sysOAuthGrantDestroy`, `sysIndexQueueStatusGet`, `sysIndexQueueStatusUpdate`, `sysIndexQueueStatusQuery`, `taskShareRevokeCleanup`, `taskDmarcReportWindow`, `taskTlsReportWindow`.

Enterprise flag added: `interactAi`, `Live.tracing`, `Live.metrics`, `Scim.access`. Roles that stored a removed permission lose it; roles carry permission names/ids that must be translated through names (ids in 1.1).

## 6. Telemetry schema

Events referenced from settings (`EventTracingLevel.event`, `TracingEventSelection.events`, `Metrics.metrics`, `Alert`, `Log.event`) are event and metric types stored as their numeric id, so the id renumbering matters for stored tracer/alert/metric selections.

- Events: 637 -> 655 (52 removed, 70 added). 558 of 585 shared events changed `id`; 290 changed `metric-id`. New metric-ids on `Ai.ApiError` (332), `Queue.BackPressure` (347), `TaskManager.TaskFailed` (361), `TaskManager.TaskRetry` (362).
- Level changes (info -> debug): `Dane.TlsaRecordNotDnssecSigned`, `Delivery.AttemptStart`, `Delivery.Completed`, `Delivery.DomainDeliveryStart`, `Delivery.Connect`, `Delivery.StartTls`, `Delivery.DsnSuccess`, `MtaSts.Authorized`, `MtaSts.PolicyFetch`, `MtaSts.PolicyNotFound`, `TlsRpt.RecordFetch`, `TlsRpt.RecordNotFound`, `Delivery.AttemptEnd`, `Delivery.StartTlsUnavailable`.
- Removed events (52):
  - `Dns.BuildError`
  - `Arc` (6): `ChainTooLong`, `InvalidInstance`, `InvalidCv`, `HasHeaderTag`, `BrokenChain`, `SealerNotFound`
  - `Dkim` (37): `UnsupportedVersion`, `UnsupportedAlgorithm`, `UnsupportedCanonicalization`, `UnsupportedKeyType`, `FailedBodyHashMatch`, `FailedVerification`, `FailedAuidMatch`, `RevokedPublicKey`, `IncompatibleAlgorithms`, `SignatureExpired`, `SignatureLength`, `InstanceMissing`, `InstanceSyntax`, `InstanceTagMissing`, `InstanceNotSigned`, `InstanceAboveSignature`, `SignatureMissing`, `SignatureSyntax`, `SignatureTagMissing`, `SignatureTagUnexpected`, `SequenceGap`, `SequenceOverflow`, `ChainTooLong`, `MailFromMismatch`, `RcptToMismatch`, `MailFromDomainMismatch`, `NextDomainMismatch`, `CustodyBreak`, `PublicKeyFetch`, `PublicKeyMissing`, `PublicKeyMultiple`, `PublicKeySyntax`, `PublicKeyAlgorithmMismatch`, `NoValidAlgorithm`, `HeaderHashMismatch`, `Modified`, `Exploded`
  - `MessageIngest.SearchIndex`
  - `Smtp.MissingAuthDirectory`, `Smtp.Dkim2DsnDiscarded` (the latter is a rename to the added `Smtp.Dkim2DsnRejected`, emitted in the same situation)
  - `Store.CacheMiss`, `CacheHit`, `CacheStale`, `CacheUpdate`, `CacheEntryTooLarge` (moved to `Cache`, below)
- Added events (70):
  - `Ai` (E): `Request`, `SpamVerdict`, `SpamSkipped`, `BreakerOpen`
  - `Arc`: `ChainInvalid`, `SignatureInvalid`, `HashMismatch`
  - `Cache` (new category, 12): `Miss`, `Hit`, `Stale`, `Update`, `EntryTooLarge`, `Invalidate`, `SwapHit`, `SwapMiss`, `SwapWrite`, `SwapError`, `SwapMetrics`, `SwapFlush`
  - `Dkim`: `SignatureInvalid`, `PublicKeyError`, `VerificationFailed`, `HashMismatch`
  - `Dkim2` (new category, 11): `InstanceInvalid`, `SignatureInvalid`, `ChainInvalid`, `TimestampInvalid`, `EnvelopeMismatch`, `CustodyBroken`, `PublicKeyError`, `VerificationFailed`, `HashMismatch`, `RecipeError`, `SigningFailed`
  - `Http.XForwardedInvalid`; `Imap.GetMetadata`, `Imap.SetMetadata`; `Jmap`: `FromAccountNotFound`, `FromAccountNotSupportedByMethod`, `ExpandDurationTooLarge`, `CannotCalculateOccurrences`, `TooLarge`, `RateLimit`, `ObjectNotFound`; `Limit.MemoryBudget`
  - `Scim` (new category, E, 12): `Request`, `Forbidden`, `Conflict`, `Error`, `ResourceCreated`, `ResourceUpdated`, `ResourceDeleted`, `Query`, `BulkProcessed`, `BulkAborted`, `RollbackFailed`, `AttributeIgnored`
  - `SearchIndex` (8): `ManagerStarted`, `PartitionsAcquired`, `PartitionLocked`, `PartitionRetry`, `BatchIndexed`, `DocumentIgnored`, `DocumentTruncated`, `MetadataNotFound`
  - `Smtp.MultipleFromDomains`, `Smtp.Dkim2DsnRejected`; `Telemetry.EventsDropped`
  - `TaskManager.TaskStalled`, `TaskManager.TaskExpired` (Tasks redesign)
- Consolidations (v0.16 reported each email authentication error as its own fine-grained event; v1 reports the same errors as umbrella events): `Arc` 6 removed / 3 added; `Dkim` 37 removed / 4 added; DKIM2 errors were reported as `Dkim.*` events in v0.16 and as the new `Dkim2.*` events in v1, and ARC signature expiry, length tag and body hash errors were reported as `Dkim.SignatureExpired`, `Dkim.SignatureLength` and `Dkim.FailedBodyHashMatch`. The per-event mapping (one old event can become several new ones) is in `mapping/v016_to_v1.toml` `[enums.EventType]`; `Arc.SealerNotFound`, `Dkim.Modified`, `Dkim.Exploded`, `Dns.BuildError`, `MessageIngest.SearchIndex` and `Smtp.MissingAuthDirectory` have no counterpart.
- Metrics: 27 -> 43. Removed: `MessageIngest.IndexTime` (moved to `SearchIndex.IndexTime`, same id 1). Added: `Ai.RequestTime`, `Ai.InputTokens`, `Ai.OutputTokens` (E); `Cache.MessagesSize`, `Cache.MessagesLargeSize`, `Cache.Size`, `Cache.SwapPending`; `SearchIndex.PendingEmail`, `PendingCalendar`, `PendingContacts`, `PendingFile`, `PendingTracing` (E); `Server.BufferedMemorySmtp`, `Server.BufferedMemoryRead`; `TaskManager.Pending`, `TaskManager.Due`.
- `Metric` records gained `nodeId` (3.3).

## 7. User schema

- `MailboxRights`, `CalendarRights`, `AddressBookRights`: + `maySetMetadata: Boolean` (default false).
- User property ids: 47 -> 48 entries (+ `maySetMetadata`), 33 shared names changed id.
- No other user schema object changed.

## 8. UI-only changes (no data impact)

- Navigation: + "Index Queue" (`x:IndexQueueStatus`), + "Metadata" (`x:Metadata`), + "Connected Applications" (`x:OAuthGrant`); "LLM Classifier" (`x:SpamLlm`) -> "AI Classifier" (`x:SpamAi`).
- Dashboards: + "Search Index" (`search-index`), "Tasks" (`tasks`), "Cache" (`cache`); series relabelled/added on existing dashboards.
- Form/list labels and field descriptions changed widely (not listed).

## 9. Items needing human review

- `OidcDirectory.requireAudience` -> `acceptedAudiences` [L], `requireScopes` dropped.
- `Http.useXForwarded` -> `clientIpSource` [L]: `true` has two candidate targets (`forwarded`, `xForwardedFor`).
- `AiModel` -> provider group [L], `SpamLlm` -> `SpamAi` field mapping [L]/[U].
- `AzureStore.accessKey/sasToken` -> `auth` [L].
- Telemetry event consolidations (`Arc`, `Dkim`) [U].
- `TaskManager.maxAttempts`/`totalDeadline` -> `alertAfter` (Tasks redesign; see 3.4).
