{{- define "meles.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "meles.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "meles.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{ include "meles.selectorLabels" . }}
{{- end }}

{{/* Labels shared by all pods of the release; the network policies rely on them. */}}
{{- define "meles.selectorLabels" -}}
app.kubernetes.io/name: {{ include "meles.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "meles.image" -}}
{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}
{{- end }}

{{- define "meles.clamdAuth" -}}
{{- if and .Values.clamd.enabled .Values.clamd.auth.enabled }}true{{ end }}
{{- end }}

{{- define "meles.clamdTokenSecret" -}}
{{- .Values.clamd.auth.existingSecret | default (printf "%s-clamd-token" (include "meles.fullname" .)) }}
{{- end }}

{{- define "meles.clamdTLSSecret" -}}
{{- .Values.clamd.auth.tls.existingSecret | default (printf "%s-clamd-tls" (include "meles.fullname" .)) }}
{{- end }}

{{/* Port of the clamd pod that clients reach: the proxy with auth. */}}
{{- define "meles.clamdPodPort" -}}
{{- if include "meles.clamdAuth" . }}3311{{ else }}3310{{ end }}
{{- end }}

{{- define "meles.clamdDnsNames" -}}
{{- $svc := printf "%s-clamd" (include "meles.fullname" .) }}
{{- $names := list $svc (printf "%s.%s" $svc .Release.Namespace) (printf "%s.%s.svc" $svc .Release.Namespace) (printf "%s.%s.svc.cluster.local" $svc .Release.Namespace) }}
{{- concat $names .Values.clamd.auth.tls.extraDnsNames | toJson }}
{{- end }}

{{/* Environment, mounts and volumes of a pod that scans with clamd. */}}
{{- define "meles.clamdClientEnv" -}}
- {name: MELES_CLAMD, value: {{ include "meles.clamdAddress" . | quote }}}
# Wait longer for a verdict than clamd may scan a file (MaxScanTime), or
# meles gives up first and the image ends as Error; at least 5 minutes.
- {name: MELES_CLAMD_TIMEOUT, value: {{ printf "%ds" (max 300 (add (div (.Values.clamd.maxScanTime | int) 1000) 60)) | quote }}}
{{- if include "meles.clamdAuth" . }}
- name: MELES_CLAMD_TOKEN
  valueFrom:
    secretKeyRef: {name: {{ include "meles.clamdTokenSecret" . }}, key: token}
- {name: MELES_CLAMD_CA, value: /clamd-ca/ca.crt}
{{- end }}
{{- end }}

{{- define "meles.clamdClientMounts" -}}
{{- if include "meles.clamdAuth" . }}
- {name: clamd-ca, mountPath: /clamd-ca, readOnly: true}
{{- end }}
{{- end }}

{{- define "meles.clamdClientVolumes" -}}
{{- if include "meles.clamdAuth" . }}
# Only the CA certificate, not the proxy's private key.
- name: clamd-ca
  secret:
    secretName: {{ include "meles.clamdTLSSecret" . }}
    items:
      - {key: ca.crt, path: ca.crt}
{{- end }}
{{- end }}

{{/* Registry mirrors and CA of a pod that pulls images. */}}
{{- define "meles.registryEnv" -}}
{{- with .Values.scan.registryMirrors }}
- {name: MELES_REGISTRY_MIRROR, value: {{ join "," . | quote }}}
{{- end }}
{{- if .Values.scan.registryCA.configMap }}
# Go reads the system roots and every file in SSL_CERT_DIR.
- {name: SSL_CERT_DIR, value: /registry-ca}
{{- end }}
{{- end }}

{{- define "meles.registryMounts" -}}
{{- if .Values.scan.registryCA.configMap }}
- {name: registry-ca, mountPath: /registry-ca, readOnly: true}
{{- end }}
{{- end }}

{{- define "meles.registryVolumes" -}}
{{- with .Values.scan.registryCA }}
{{- if .configMap }}
- name: registry-ca
  configMap:
    name: {{ .configMap }}
    items:
      - {key: {{ .key }}, path: ca.crt}
{{- end }}
{{- end }}
{{- end }}

{{- define "meles.clamdAddress" -}}
{{- if include "meles.clamdAuth" . }}
{{- printf "tls://%s-clamd:3310" (include "meles.fullname" .) }}
{{- else if .Values.clamd.enabled }}
{{- printf "tcp://%s-clamd:3310" (include "meles.fullname" .) }}
{{- else }}
{{- required "clamd.address is required if clamd.enabled is false" .Values.clamd.address }}
{{- end }}
{{- end }}

{{/* Port of the server pod that clients reach: oauth2-proxy if enabled. */}}
{{- define "meles.serverPodPort" -}}
{{- if .Values.server.oauth2Proxy.enabled }}4180{{ else }}8080{{ end }}
{{- end }}

{{- define "meles.imagePullSecrets" -}}
{{- with .Values.imagePullSecrets }}
imagePullSecrets:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end }}

{{/* File names of the YARA rules the mirror serves, one per line. */}}
{{- define "meles.yaraFiles" -}}
{{- if .Values.mirror.enabled }}
{{- if .Values.yara.defaultRules }}
meles.yar
{{ end }}
{{- range .Values.yara.extra }}
{{- range .files }}
{{- if not (hasSuffix ".yar" .) }}
{{- fail (printf "yara.extra: %q must end in .yar" .) }}
{{- end }}
{{- if eq . "meles.yar" }}
{{- fail "yara.extra: meles.yar is the name of the default rules" }}
{{- end }}
{{ . }}
{{ end }}
{{- end }}
{{- end }}
{{- end }}

{{- define "meles.scheduling" -}}
{{- with .nodeSelector }}
nodeSelector:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .tolerations }}
tolerations:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .affinity }}
affinity:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end }}

{{/* Bytes of a size such as 25M, 2047M or 512K (as meles parses it). */}}
{{- define "meles.bytes" -}}
{{- $v := upper (toString .) | trimSuffix "B" | trimSuffix "I" -}}
{{- $mult := 1 -}}
{{- if hasSuffix "K" $v }}{{ $mult = 1024 }}{{ $v = trimSuffix "K" $v }}
{{- else if hasSuffix "M" $v }}{{ $mult = 1048576 }}{{ $v = trimSuffix "M" $v }}
{{- else if hasSuffix "G" $v }}{{ $mult = 1073741824 }}{{ $v = trimSuffix "G" $v }}
{{- end -}}
{{- if not (regexMatch "^[0-9]+$" $v) }}{{ fail (printf "invalid size %q (examples: 512K, 25M, 2047M)" (toString .)) }}{{ end -}}
{{- mul (atoi $v) $mult -}}
{{- end }}

{{/*
"true" if the server shows the operator's MalwareReports: server.clusterReports.enabled,
or operator.enabled if that is not set.
*/}}
{{- define "meles.clusterReports" -}}
{{- $on := .Values.server.clusterReports.enabled -}}
{{- if kindIs "invalid" $on }}{{ $on = .Values.operator.enabled }}{{ end -}}
{{- if and .Values.server.enabled $on }}true{{ end -}}
{{- end }}

{{/*
URL of the web UI, for links in alerts: operator.prometheusRule.uiURL, else
from the server's ingress or HTTPRoute; empty if none is known.
*/}}
{{- define "meles.uiURL" -}}
{{- $s := .Values.server }}
{{- if .Values.operator.prometheusRule.uiURL }}
{{- trimSuffix "/" .Values.operator.prometheusRule.uiURL }}
{{- else if and $s.enabled $s.ingress.enabled $s.ingress.host }}
{{- printf "http%s://%s" (ternary "s" "" (not (empty $s.ingress.tls))) $s.ingress.host }}
{{- else if and $s.enabled $s.httpRoute.enabled $s.httpRoute.hostnames }}
{{- printf "https://%s" (first $s.httpRoute.hostnames) }}
{{- end }}
{{- end }}
