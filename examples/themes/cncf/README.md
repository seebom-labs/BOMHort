# CNCF-inspired theme

A `custom-theme.css` + `ui-config.json` pair that restyles BOMHort with the
public [CNCF colour palette](https://www.cncf.io/brand-guidelines/)
(CNCF Blue `#0086FF`, Black, Turquoise `#93EAFF`, Pink `#D62293`, Stone
`#E5E5E5`) and the Clarity City font stack, similar in feel to
[contribute.cncf.io](https://contribute.cncf.io/contributors/).

Light navbar (white, Stone rule, CNCF Blue active link), CNCF Blue accent,
Pink for critical findings, and the CNCF wordmark in place of the mascot:
`brand/cncf-logo.svg` (unmodified primary logo) in light mode and
`brand/cncf-logo-dark.svg` (the official all-white variant) in dark mode via
`brandLogo` / `brandLogoDark`.

```bash
# Docker Compose
CUSTOM_THEME=./examples/themes/cncf/custom-theme.css \
UI_CONFIG=./examples/themes/cncf/ui-config.json \
BRAND_ASSETS=./examples/themes/cncf/brand \
make dev
```

```bash
# Kubernetes – create the theme ConfigMap and reference it in the Helm values
# (ui.siteConfig.content carries the ui-config.json keys)
kubectl create configmap bomhort-theme --from-file=custom-theme.css=examples/themes/cncf/custom-theme.css
helm upgrade bomhort deploy/helm/bomhort --reuse-values \
  --set ui.customTheme.enabled=true \
  --set ui.customTheme.existingConfigMap=bomhort-theme
```

**Trademark note.** The [brand guidelines](https://www.cncf.io/brand-guidelines/)
require the logo to be used unmodified and ask that websites check in with
`brand@linuxfoundation.org` before using it; "Member of CNCF" or a CNCF
project's own deployment is the intended case. Keep the attribution in the
disclaimer, or drop `brandLogo` from `ui-config.json` to run with colours only.
