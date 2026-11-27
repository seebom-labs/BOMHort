{{- /*
Private vulnerabilities: where the API gateway and the parsing workers read them
from. Shared by both deployments and the config ConfigMap so the mount, the
volume and PRIVATE_VULNERABILITIES_* can never disagree.

Three mutually exclusive sources:
  custom (default)      rendered into <release>-private-vulnerabilities
  existingConfigMap     a ConfigMap managed outside the chart
  source                an https:// URL or s3://bucket/key, fetched by the pods
*/ -}}

{{- define "bomhort.privateVulnerabilities.source" -}}
{{- $pv := .Values.privateVulnerabilities | default dict -}}
{{- if $pv.enabled }}{{ $pv.source | default "" | trim }}{{ end -}}
{{- end -}}

{{- /* "true" when a ConfigMap is mounted into the pods. */ -}}
{{- define "bomhort.privateVulnerabilities.mounted" -}}
{{- $pv := .Values.privateVulnerabilities | default dict -}}
{{- if and $pv.enabled (not (include "bomhort.privateVulnerabilities.source" .)) }}true{{ end -}}
{{- end -}}

{{- define "bomhort.privateVulnerabilities.file" -}}
{{- $pv := .Values.privateVulnerabilities | default dict -}}
{{- $path := $pv.mountPath | default "/data/config/private-vulnerabilities/private-vulnerabilities.json" -}}
{{- if eq $path "/data/config/private-vulnerabilities.json" -}}
{{- $path = "/data/config/private-vulnerabilities/private-vulnerabilities.json" -}}
{{- end -}}
{{- $path -}}
{{- end -}}

{{- define "bomhort.privateVulnerabilities.refreshInterval" -}}
{{- $pv := .Values.privateVulnerabilities | default dict -}}
{{- $v := $pv.refreshInterval -}}
{{- if or (kindIs "invalid" $v) (and (kindIs "string" $v) (eq $v "")) }}60s{{ else }}{{ $v | toString }}{{ end -}}
{{- end -}}

{{- define "bomhort.privateVulnerabilities.customSet" -}}
{{- $pv := .Values.privateVulnerabilities | default dict -}}
{{- if not (or (kindIs "invalid" $pv.custom) (and (kindIs "string" $pv.custom) (eq ($pv.custom | trim) "")) (and (kindIs "slice" $pv.custom) (eq (len $pv.custom) 0))) }}true{{ end -}}
{{- end -}}

{{- define "bomhort.privateVulnerabilities.validate" -}}
{{- $pv := .Values.privateVulnerabilities | default dict -}}
{{- if $pv.enabled -}}
{{- $customSet := include "bomhort.privateVulnerabilities.customSet" . -}}
{{- $source := include "bomhort.privateVulnerabilities.source" . -}}
{{- if and $pv.existingConfigMap $customSet -}}
{{- fail "privateVulnerabilities.existingConfigMap and privateVulnerabilities.custom are mutually exclusive: set one of them, not both" -}}
{{- end -}}
{{- if and $source (or $pv.existingConfigMap $customSet) -}}
{{- fail "privateVulnerabilities.source is mutually exclusive with privateVulnerabilities.custom and privateVulnerabilities.existingConfigMap: set one of them" -}}
{{- end -}}
{{- if $customSet -}}
{{- $decoded := $pv.custom -}}
{{- if kindIs "string" $pv.custom -}}
{{- $decoded = mustFromJson $pv.custom -}}
{{- end -}}
{{- $validShape := false -}}
{{- if kindIs "slice" $decoded -}}
{{- $validShape = true -}}
{{- else if and (kindIs "map" $decoded) (hasKey $decoded "vulnerabilities") (kindIs "slice" $decoded.vulnerabilities) -}}
{{- $validShape = true -}}
{{- end -}}
{{- if not $validShape -}}
{{- fail "privateVulnerabilities.custom must be an array of OSV advisory objects (or JSON wrapper with vulnerabilities array)" -}}
{{- end -}}
{{- end -}}
{{- if and $source (not (or (hasPrefix "https://" $source) (hasPrefix "s3://" $source))) -}}
{{- fail (printf "privateVulnerabilities.source must be an https:// URL or s3://bucket/key (got %q)" $source) -}}
{{- end -}}
{{- $secret := $pv.sourceTokenSecret | default dict -}}
{{- if and $secret.name (not $source) -}}
{{- fail "privateVulnerabilities.sourceTokenSecret is only used with privateVulnerabilities.source" -}}
{{- end -}}
{{- $interval := include "bomhort.privateVulnerabilities.refreshInterval" . -}}
{{- if not (regexMatch "^(0|([0-9]+(\\.[0-9]+)?(ns|us|ms|s|m|h))+)$" $interval) -}}
{{- fail (printf "privateVulnerabilities.refreshInterval must be a duration such as 60s or 5m, or 0 to disable reloading (got %q)" $interval) -}}
{{- end -}}
{{- if include "bomhort.privateVulnerabilities.mounted" . -}}
{{- $dir := dir (include "bomhort.privateVulnerabilities.file" .) -}}
{{- if eq $dir "/" -}}
{{- fail "privateVulnerabilities.mountPath must be a file inside a directory of its own, e.g. /data/config/private-vulnerabilities/private-vulnerabilities.json" -}}
{{- end -}}
{{- $taken := list -}}
{{- if .Values.licensePolicy.enabled }}{{ $taken = append $taken (dir .Values.licensePolicy.mountPath) }}{{ end -}}
{{- if include "bomhort.licenseExceptions.mounted" . }}{{ $taken = append $taken (dir (include "bomhort.licenseExceptions.file" .)) }}{{ end -}}
{{- $pg := .Values.projectGroups | default dict -}}
{{- if $pg.enabled }}{{ $taken = append $taken ($pg.mountDir | default "/data/config/project-groups" | trimSuffix "/") }}{{ end -}}
{{- $taken = append $taken (.Values.sbomSource.mountPath | trimSuffix "/") -}}
{{- range $taken -}}
{{- if or (eq . $dir) (hasPrefix (printf "%s/" $dir) .) -}}
{{- fail (printf "privateVulnerabilities.mountPath: its directory %s collides with the mount at %s; give private vulnerabilities a directory of its own, e.g. /data/config/private-vulnerabilities/private-vulnerabilities.json" $dir .) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "bomhort.privateVulnerabilities.volumeMount" -}}
{{- if include "bomhort.privateVulnerabilities.mounted" . }}
- name: private-vulnerabilities
  mountPath: {{ dir (include "bomhort.privateVulnerabilities.file" .) }}
  readOnly: true
{{- end }}
{{- end -}}

{{- define "bomhort.privateVulnerabilities.volume" -}}
{{- if include "bomhort.privateVulnerabilities.mounted" . }}
{{- $pv := .Values.privateVulnerabilities | default dict }}
- name: private-vulnerabilities
  configMap:
    {{- if $pv.existingConfigMap }}
    name: {{ $pv.existingConfigMap }}
    items:
      - key: {{ $pv.existingConfigMapKey | default "private-vulnerabilities.json" }}
        path: {{ base (include "bomhort.privateVulnerabilities.file" .) }}
    {{- else }}
    name: {{ .Release.Name }}-private-vulnerabilities
    {{- if ne (base (include "bomhort.privateVulnerabilities.file" .)) "private-vulnerabilities.json" }}
    items:
      - key: private-vulnerabilities.json
        path: {{ base (include "bomhort.privateVulnerabilities.file" .) }}
    {{- end }}
    {{- end }}
{{- end }}
{{- end -}}

{{- define "bomhort.privateVulnerabilities.env" -}}
{{- $pv := .Values.privateVulnerabilities | default dict }}
{{- $secret := $pv.sourceTokenSecret | default dict }}
{{- if and (include "bomhort.privateVulnerabilities.source" .) $secret.name }}
- name: PRIVATE_VULNERABILITIES_SOURCE_TOKEN
  valueFrom:
    secretKeyRef:
      name: {{ $secret.name }}
      key: {{ $secret.key | default "token" }}
{{- end }}
{{- end -}}
