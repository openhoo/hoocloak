{{- define "hoocloak.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "hoocloak.fullname" -}}
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

{{- define "hoocloak.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "hoocloak.image" -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}
{{- end }}

{{- define "hoocloak.validateValues" -}}
{{- if hasKey .Values.podLabels "app.kubernetes.io/name" -}}
{{- fail "podLabels must not override app.kubernetes.io/name" -}}
{{- end -}}
{{- if hasKey .Values.podLabels "app.kubernetes.io/instance" -}}
{{- fail "podLabels must not override app.kubernetes.io/instance" -}}
{{- end -}}
{{- if hasKey .Values.podAnnotations "checksum/config" -}}
{{- fail "podAnnotations must not override checksum/config" -}}
{{- end -}}
{{- if hasKey .Values.podAnnotations "checksum/external-config" -}}
{{- fail "podAnnotations must not override checksum/external-config" -}}
{{- end -}}
{{- end }}

{{- define "hoocloak.labels" -}}
helm.sh/chart: {{ include "hoocloak.chart" . }}
{{ include "hoocloak.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}

{{- define "hoocloak.selectorLabels" -}}
app.kubernetes.io/name: {{ include "hoocloak.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "hoocloak.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "hoocloak.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "hoocloak.configSecretName" -}}
{{- default (printf "%s-config" (include "hoocloak.fullname" .)) .Values.existingConfigSecret }}
{{- end }}
