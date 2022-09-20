{{/* vim: set filetype=mustache: */}}
{{/*
Expand the name of the chart.
*/}}
{{- define "deepfence-k8s-scanner.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "deepfence-k8s-scanner.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "deepfence-k8s-scanner.labels" -}}
helm.sh/chart: {{ include "deepfence-k8s-scanner.chart" . }}
{{ include "deepfence-k8s-scanner.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "deepfence-k8s-scanner.selectorLabels" -}}
app.kubernetes.io/name: {{ include "deepfence-k8s-scanner.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}