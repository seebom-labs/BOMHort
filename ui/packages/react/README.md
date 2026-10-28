# @bomhort/react

Typed React components over the BOMHort web components. Load the elements bundle once, then use the wrappers:

```html
<script>window.BOMHORT_API_URL = 'https://bomhort.example/api/v1';</script>
<link rel="stylesheet" href="/bomhort-elements/styles.css" />
<script type="module" src="/bomhort-elements/main.js"></script>
```

```tsx
import { DonutChart, BomhortPage } from '@bomhort/react';

<DonutChart segments={[{ label: 'Critical', value: 2, color: '#C43030' }]} centerLabel="2" />
<div style={{ height: 700 }}>
  <BomhortPage route="/projects/my-service" onNavigate={(e) => console.log('now at', e.detail)} />
</div>
```

Attributes/strings go through as attributes; objects and arrays are set as DOM properties after mount. Data
access without any component: `@bomhort/api-client`.
