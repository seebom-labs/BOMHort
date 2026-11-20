{{- /*
ClickHouse TLS configuration is shared by every backend workload and by both
ClickHouse CLI migration jobs. Certificates and private keys are always read
from an existing Secret; chart values contain only Secret keys and mount paths.
*/ -}}

{{- define "bomhort.clickhouseTLS.validate" -}}
{{- $tls := .Values.clickhouse.tls | default dict -}}
{{- $enabled := $tls.enabled | default false -}}
{{- $skipVerify := $tls.skipVerify | default false -}}
{{- $secret := $tls.existingSecret | default "" -}}
{{- $ca := $tls.caKey | default "" -}}
{{- $cert := $tls.clientCertKey | default "" -}}
{{- $key := $tls.clientKeyKey | default "" -}}
{{- if not (kindIs "bool" $enabled) -}}
{{- fail "clickhouse.tls.enabled must be a boolean" -}}
{{- end -}}
{{- if not (kindIs "bool" $skipVerify) -}}
{{- fail "clickhouse.tls.skipVerify must be a boolean" -}}
{{- end -}}
{{- if and (not $enabled) (or $skipVerify $secret $ca $cert $key) -}}
{{- fail "clickhouse.tls settings require clickhouse.tls.enabled=true" -}}
{{- end -}}
{{- if ne (eq $cert "") (eq $key "") -}}
{{- fail "clickhouse.tls.clientCertKey and clientKeyKey must be configured together" -}}
{{- end -}}
{{- if and (or $ca $cert $key) (not $secret) -}}
{{- fail "clickhouse.tls.existingSecret is required when CA or client certificate keys are configured" -}}
{{- end -}}
{{- if and $secret (not (or $ca $cert $key)) -}}
{{- fail "clickhouse.tls.existingSecret requires at least one of caKey, clientCertKey, or clientKeyKey" -}}
{{- end -}}
{{- if $secret -}}
{{- $mountPath := $tls.mountPath | default "/etc/bomhort/clickhouse-tls" -}}
{{- if not (hasPrefix "/" $mountPath) -}}
{{- fail "clickhouse.tls.mountPath must be an absolute path" -}}
{{- end -}}
{{- range (list $ca $cert $key) -}}
{{- if and . (not (regexMatch "^[A-Za-z0-9._-]+$" .)) -}}
{{- fail (printf "clickhouse.tls Secret keys must be simple file names (got %q)" .) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "bomhort.clickhouseTLS.caFile" -}}
{{- $tls := .Values.clickhouse.tls | default dict -}}
{{- if and ($tls.enabled | default false) ($tls.caKey | default "") -}}
{{- printf "%s/%s" (trimSuffix "/" ($tls.mountPath | default "/etc/bomhort/clickhouse-tls")) $tls.caKey -}}
{{- end -}}
{{- end -}}

{{- define "bomhort.clickhouseTLS.clientCertFile" -}}
{{- $tls := .Values.clickhouse.tls | default dict -}}
{{- if and ($tls.enabled | default false) ($tls.clientCertKey | default "") -}}
{{- printf "%s/%s" (trimSuffix "/" ($tls.mountPath | default "/etc/bomhort/clickhouse-tls")) $tls.clientCertKey -}}
{{- end -}}
{{- end -}}

{{- define "bomhort.clickhouseTLS.clientKeyFile" -}}
{{- $tls := .Values.clickhouse.tls | default dict -}}
{{- if and ($tls.enabled | default false) ($tls.clientKeyKey | default "") -}}
{{- printf "%s/%s" (trimSuffix "/" ($tls.mountPath | default "/etc/bomhort/clickhouse-tls")) $tls.clientKeyKey -}}
{{- end -}}
{{- end -}}

{{- define "bomhort.clickhouseTLS.volumeMount" -}}
{{- $tls := .Values.clickhouse.tls | default dict -}}
{{- if and ($tls.enabled | default false) ($tls.existingSecret | default "") (or ($tls.caKey | default "") ($tls.clientCertKey | default "") ($tls.clientKeyKey | default "")) }}
- name: clickhouse-tls
  mountPath: {{ $tls.mountPath | default "/etc/bomhort/clickhouse-tls" | quote }}
  readOnly: true
{{- end -}}
{{- end -}}

{{- define "bomhort.clickhouseTLS.volume" -}}
{{- $tls := .Values.clickhouse.tls | default dict -}}
{{- if and ($tls.enabled | default false) ($tls.existingSecret | default "") (or ($tls.caKey | default "") ($tls.clientCertKey | default "") ($tls.clientKeyKey | default "")) }}
- name: clickhouse-tls
  secret:
    secretName: {{ $tls.existingSecret | quote }}
    defaultMode: 0440
    items:
      {{- with ($tls.caKey | default "") }}
      - key: {{ . | quote }}
        path: {{ . | quote }}
      {{- end }}
      {{- with ($tls.clientCertKey | default "") }}
      - key: {{ . | quote }}
        path: {{ . | quote }}
      {{- end }}
      {{- with ($tls.clientKeyKey | default "") }}
      - key: {{ . | quote }}
        path: {{ . | quote }}
      {{- end }}
{{- end -}}
{{- end -}}

{{- define "bomhort.clickhouseTLS.clientConfig" -}}
{{- $tls := .Values.clickhouse.tls | default dict -}}
<?xml version="1.0"?>
<config>
  <openSSL>
    <client>
      <loadDefaultCAFile>true</loadDefaultCAFile>
      {{- with (include "bomhort.clickhouseTLS.caFile" .) }}
      <caConfig>{{ . }}</caConfig>
      {{- end }}
      {{- with (include "bomhort.clickhouseTLS.clientCertFile" .) }}
      <certificateFile>{{ . }}</certificateFile>
      {{- end }}
      {{- with (include "bomhort.clickhouseTLS.clientKeyFile" .) }}
      <privateKeyFile>{{ . }}</privateKeyFile>
      {{- end }}
      {{- if $tls.skipVerify }}
      <verificationMode>none</verificationMode>
      <invalidCertificateHandler><name>AcceptCertificateHandler</name></invalidCertificateHandler>
      {{- else }}
      <verificationMode>strict</verificationMode>
      <invalidCertificateHandler><name>RejectCertificateHandler</name></invalidCertificateHandler>
      {{- end }}
    </client>
  </openSSL>
</config>
{{- end -}}
