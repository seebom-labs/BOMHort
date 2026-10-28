# @bomhort/api-client

Typed, zero-dependency client for the BOMHort REST API (`GET` only — the API is read-only for consumers).
Works in browsers, Node ≥ 18, Deno, and any framework.

```ts
import { BomhortApiClient } from '@bomhort/api-client';

const api = new BomhortApiClient({ baseUrl: 'https://bomhort.example.com/api/v1', apiKey: '…' });
const { data, total } = await api.getVulnerabilities(1, 50, 'direct');
```

Method names, parameters and defaults mirror the Angular `ApiService` in `ui/src/app/core/api.service.ts`;
a test keeps the two in sync. Errors are thrown as `ApiError { status, url, body }`. Every method takes an
optional trailing `AbortSignal`.
