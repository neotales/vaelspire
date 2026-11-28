{{- define "vaelspire.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "vaelspire.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "vaelspire.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "vaelspire.labels" -}}
app.kubernetes.io/name: {{ include "vaelspire.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "vaelspire.selectorLabels" -}}
app.kubernetes.io/name: {{ include "vaelspire.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
