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

{{- define "hoocloak.validateIngress" -}}
{{- $hostConfig := first .Values.ingress.hosts -}}
{{- $host := required "ingress host must not be empty" $hostConfig.host -}}
{{- $expectedBaseURL := printf "https://%s/" $host -}}
{{- $baseURL := .Values.hoocloakConfig.base_url -}}
{{- $baseURLName := "hoocloakConfig.base_url" -}}
{{- if .Values.existingConfigSecret -}}
{{- $baseURL = required "existingConfigBaseURL is required when existingConfigSecret and ingress are enabled" .Values.existingConfigBaseURL -}}
{{- $baseURLName = "existingConfigBaseURL" -}}
{{- end -}}
{{- if ne $baseURL $expectedBaseURL -}}
{{- fail (printf "%s must be the canonical root HTTPS URL %s for ingress host %s" $baseURLName $expectedBaseURL $host) -}}
{{- end -}}
{{- range $hostConfig.paths -}}
{{- if or (ne .path "/") (ne .pathType "Prefix") -}}
{{- fail "ingress routes support only path / with pathType Prefix" -}}
{{- end -}}
{{- end -}}
{{- $covered := false -}}
{{- range .Values.ingress.tls -}}
{{- if has $host (default (list) .hosts) -}}
{{- $covered = true -}}
{{- end -}}
{{- end -}}
{{- if not $covered -}}
{{- fail (printf "ingress TLS must cover host %s" $host) -}}
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
{{- if .Values.theme.image.reference -}}
{{- if ne (int64 (default 0 .Values.podSecurityContext.fsGroup)) (int64 (default -1 .Values.securityContext.runAsGroup)) -}}
{{- fail "theme.image.reference requires podSecurityContext.fsGroup to equal securityContext.runAsGroup so the non-root init container can write the theme volume" -}}
{{- end -}}
{{- end -}}
{{- if and (not .Values.existingConfigSecret) .Values.theme.image.reference .Values.hoocloakConfig.ui -}}
{{- if and .Values.hoocloakConfig.ui.theme_dir (ne .Values.hoocloakConfig.ui.theme_dir .Values.theme.mountPath) -}}
{{- fail (printf "hoocloakConfig.ui.theme_dir must equal theme.mountPath %s when theme.image.reference is configured" .Values.theme.mountPath) -}}
{{- end -}}
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
