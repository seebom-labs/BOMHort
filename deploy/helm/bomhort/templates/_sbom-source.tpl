{{- /*
The sbom-data volume: where the ingestion watcher, the parsing workers and the
API gateway read SBOMs from the local filesystem. Shared by the PVC and the
three workloads so the claim, the mounts and the co-scheduling rules can never
disagree.

Three modes:
  gitSync.enabled=true           an emptyDir filled by git-sync, no PVC
  sbomSource.enabled=true        the sbomSource PVC (default without git-sync)
  sbomSource.enabled=false       no volume at all, for S3-only deployments (#590)
*/ -}}

{{- /*
"true" when the chart creates and mounts the sbomSource PVC. `enabled` is
absent after `helm upgrade --reuse-values` from a chart that predates it;
that means enabled, so such an upgrade never drops a PVC that is in use.
*/ -}}
{{- define "bomhort.sbomSource.pvc" -}}
{{- $enabled := (.Values.sbomSource | default dict).enabled -}}
{{- if and (not .Values.gitSync.enabled) (or (kindIs "invalid" $enabled) $enabled) }}true{{ end -}}
{{- end -}}

{{- /* "true" when the pods mount a sbom-data volume, emptyDir or PVC. */ -}}
{{- define "bomhort.sbomSource.mounted" -}}
{{- if or .Values.gitSync.enabled (include "bomhort.sbomSource.pvc" .) }}true{{ end -}}
{{- end -}}

{{- /*
"true" when the parsing workers and the API gateway must share a node. They
are co-scheduled for the sbomSource PVC, and the originals PVC
(originalStore.fs) has always relied on that same rule, so it keeps the pods
together when the sbomSource PVC is gone. git-sync mode never had the rule.
*/ -}}
{{- define "bomhort.sbomSource.colocate" -}}
{{- if and (not .Values.gitSync.enabled) (or (include "bomhort.sbomSource.pvc" .) .Values.originalStore.fs.enabled) }}true{{ end -}}
{{- end -}}

{{- define "bomhort.sbomSource.validate" -}}
{{- if not (include "bomhort.sbomSource.mounted" .) -}}
{{- if not .Values.s3.buckets -}}
{{- fail "sbomSource.enabled=false leaves BOMHort without an SBOM source: set s3.buckets, or keep the volume (sbomSource.enabled=true) or use gitSync.enabled=true" -}}
{{- end -}}
{{- if .Values.sbomSource.writable -}}
{{- fail "sbomSource.writable=true needs the sbom-data volume, which sbomSource.enabled=false removes: drop sbomSource.writable and send push uploads to an s3.buckets entry marked \"skipScan\": true, or set sbomSource.enabled=true" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- /*
Pod label, affinity and volume, rendered from the rules above so the three
workloads cannot drift apart. The label and the affinity take
(dict "root" $ "originals" <bool>): "originals" is true for the pods that
mount the originals PVC (parsing workers, API gateway) and are therefore
co-scheduled by the colocate rule; the ingestion watcher passes false and is
only pinned for the sbomSource PVC.
*/ -}}
{{- define "bomhort.sbomSource.pinned" -}}
{{- if .originals }}{{ include "bomhort.sbomSource.colocate" .root }}{{ else }}{{ include "bomhort.sbomSource.pvc" .root }}{{ end -}}
{{- end -}}

{{- define "bomhort.sbomSource.podLabel" -}}
{{- if include "bomhort.sbomSource.pinned" . }}
bomhort.io/sbom-volume: "true"
{{- end }}
{{- end -}}

{{- define "bomhort.sbomSource.affinity" -}}
{{- if include "bomhort.sbomSource.pinned" . }}
affinity:
  podAffinity:
    requiredDuringSchedulingIgnoredDuringExecution:
      - labelSelector:
          matchExpressions:
            - key: bomhort.io/sbom-volume
              operator: Exists
        topologyKey: kubernetes.io/hostname
{{- end }}
{{- end -}}

{{- /* The sbom-data volume entry, or nothing without a mount. */ -}}
{{- define "bomhort.sbomSource.volume" -}}
{{- if .Values.gitSync.enabled }}
- name: sbom-data
  emptyDir: {}
{{- else if include "bomhort.sbomSource.pvc" . }}
- name: sbom-data
  persistentVolumeClaim:
    claimName: {{ .Values.sbomSource.pvcName }}
{{- end }}
{{- end -}}
