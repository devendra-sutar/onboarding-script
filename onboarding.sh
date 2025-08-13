#!/bin/bash

# Kubernetes Service Account Creation and Unified Deployment
# Supports Rancher proxy URLs and direct API URLs
# Handles RKE2, k3s, and standard Kubernetes configurations
# Creates a service account with cluster-admin permissions and deploys monitoring and security tools
# Allows custom username, skips for deployments, and dry-run mode

set -e
set -o pipefail

### Configuration Variables
NAMESPACE="kube-system"
KUBE_CONFIG="${KUBE_CONFIG:-}"
RKE2_DEFAULT_CONFIG="/etc/rancher/rke2/rke2.yaml"
K3S_DEFAULT_CONFIG="/etc/rancher/k3s/k3s.yaml"
OUTPUT_CA_CRT="/tmp/ca.crt"
EXPORT_FILE="/tmp/k8s-credentials.env"
VALUES_TEMPLATE="values-template.yaml"
DEFAULT_OS_USERNAME="default-user"
DEFAULT_OS_PASSWORD="default-password"
DEFAULT_OS_HOST="https://10.0.33.244:9200"
DEFAULT_WEBHOOK_ENDPOINT="https://webhook.si/daf6-dcc7-414c-9e50-afd6d3e7ce94"
DEFAULT_WEBHOOK_USER_NAME="sudhakar"
DEFAULT_WEBHOOK_USER_AGENT="bash-deployment-script"
DEFAULT_WEBHOOK_AUTH_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI0IiwiZXhwIjoxNzQ5OTAwNzAwfQ.ThR-a3St6iegmjeOOuGgcV3UIo8x3FMsrJhyjjJADVE"
DEFAULT_PROMETHEUS_HOST="http://10.0.2.13:9090"
DEFAULT_LOKI_HOST="http://10.0.2.13:3100"
DEFAULT_TEMPO_HOST="http://10.0.2.13:3200"
DEFAULT_NAMESPACE="default"

### Color Codes for Output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

### Logging Functions
log_info() { echo -e "${BLUE}[INFO]${NC} $1" >&2; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1" >&2; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1" >&2; }

### Progress Bar Variables
TOTAL_STEPS=15
CURRENT_STEP=0

show_progress() {
    local percent=$(( CURRENT_STEP * 100 / TOTAL_STEPS ))
    local bar_width=50
    local filled=$(( percent * bar_width / 100 ))
    local empty=$(( bar_width - filled ))
    printf "\r["
    printf "%0.s#" $(seq 1 $filled)
    printf "%0.s-" $(seq 1 $empty)
    printf "] %3d%%" "$percent"
    if [ "$CURRENT_STEP" -eq "$TOTAL_STEPS" ]; then
        echo
    fi
}

# Wrapper to run a step with progress and success message
run_step() {
    local func="$1"
    local func_name=$(echo "$func" | sed 's/_step$//')
    shift
    local percent=$(( CURRENT_STEP * 100 / TOTAL_STEPS ))
    log_info "Starting $func_name (${percent}% complete)..."
    { "$func" "$@" > /dev/null 2>&1; } || {
        log_error "Step $func_name failed."
        exit 1
    }
    CURRENT_STEP=$((CURRENT_STEP + 1))
    show_progress
    log_success "$func_name completed successfully"
}

### Check Directory Writability
if ! touch test-write-file 2>/dev/null; then
    log_error "Current directory is not writable. Switching to /tmp for output files."
    OUTPUT_DIR="/tmp"
else
    OUTPUT_DIR="$(pwd)"
    rm -f test-write-file
fi

### Usage Information
show_usage() {
    cat << EOF
Usage: $0 <CLUSTER_NAME> [USERNAME] [WEBHOOK_ENDPOINT] [OPTIONS]

Create Service Account and Deploy Tools for Rancher-Managed Kubernetes Clusters
Supports Rancher proxy URLs[](https://<rancher>/k8s/clusters/...) and direct API URLs[](https://<ip>:6443)
Handles RKE2, k3s, and standard Kubernetes configurations

ARGUMENTS:
    CLUSTER_NAME                    Name of the Kubernetes cluster (required)
    USERNAME                        Username for service account (optional, default: admin-user, or K8S_USERNAME env)
    WEBHOOK_ENDPOINT                Webhook endpoint URL (optional, default: $DEFAULT_WEBHOOK_ENDPOINT)

OPTIONS:
    --username USERNAME             Service account username (overrides positional USERNAME)
    --config-path PATH              Path to kubeconfig file (default: checks RKE2, k3s, then ~/.kube/config)
    --os-username USERNAME          OpenSearch username (default: $DEFAULT_OS_USERNAME)
    --os-password PASSWORD          OpenSearch password (default: $DEFAULT_OS_PASSWORD)
    --os-host HOST                  OpenSearch host URL (default: $DEFAULT_OS_HOST)
    --webhook-endpoint URL          Webhook endpoint URL (overrides positional WEBHOOK_ENDPOINT)
    --webhook-user-name NAME        Webhook user name (default: $DEFAULT_WEBHOOK_USER_NAME)
    --webhook-user-agent AGENT      Webhook user agent (default: $DEFAULT_WEBHOOK_USER_AGENT)
    --webhook-auth-token TOKEN      Webhook authorization token (default: using default token)
    -n, --namespace NAMESPACE       Kubernetes namespace (default: $NAMESPACE)
    --prometheus-host URL           Prometheus host URL (default: $DEFAULT_PROMETHEUS_HOST)
    --loki-host URL                 Loki host URL (default: $DEFAULT_LOKI_HOST)
    --tempo-host URL                Tempo host URL (default: $DEFAULT_TEMPO_HOST)
    --values-template PATH          Path to values template file (default: $VALUES_TEMPLATE)
    --skip-event-exporter           Skip event exporter deployment
    --skip-monitoring               Skip monitoring stack deployment
    --skip-cost-analysis            Skip cost analysis tools (Kepler, OpenCost)
    --skip-webhook                  Skip webhook notification
    --skip-trivy                    Skip Trivy operator installation
    --skip-kyverno                  Skip Kyverno installation
    --dry-run                       Show what would be deployed without executing
    -h, --help                      Show this help message

EXAMPLES:
    $0 "my-cluster" "admin-user" "http://webhook.com"
    $0 "my-cluster" --config-path /etc/rancher/k3s/k3s.yaml --username "team-user" "http://webhook.com"
    K8S_USERNAME="team-user" $0 "my-cluster" --skip-cost-analysis "http://webhook.com"
    $0 "my-cluster" --dry-run "http://webhook.com"
EOF
    exit 0
}

### Parse Arguments
CLUSTER_NAME=""
USERNAME="${K8S_USERNAME:-admin-user}"
WEBHOOK_ENDPOINT="$DEFAULT_WEBHOOK_ENDPOINT"
OS_USERNAME="$DEFAULT_OS_USERNAME"
OS_PASSWORD="$DEFAULT_OS_PASSWORD"
OS_HOST="$DEFAULT_OS_HOST"
WEBHOOK_USER_NAME="$DEFAULT_WEBHOOK_USER_NAME"
WEBHOOK_USER_AGENT="$DEFAULT_WEBHOOK_USER_AGENT"
WEBHOOK_AUTH_TOKEN="$DEFAULT_WEBHOOK_AUTH_TOKEN"
PROMETHEUS_HOST="$DEFAULT_PROMETHEUS_HOST"
LOKI_HOST="$DEFAULT_LOKI_HOST"
TEMPO_HOST="$DEFAULT_TEMPO_HOST"
DRY_RUN=false
SKIP_EVENT_EXPORTER=false
SKIP_MONITORING=false
SKIP_COST_ANALYSIS=false
SKIP_WEBHOOK=false
SKIP_TRIVY=false
SKIP_KYVERNO=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --username) USERNAME="$2"; shift 2;;
        --config-path) KUBE_CONFIG="$2"; shift 2;;
        -n|--namespace) NAMESPACE="$2"; shift 2;;
        --os-username) OS_USERNAME="$2"; shift 2;;
        --os-password) OS_PASSWORD="$2"; shift 2;;
        --os-host) OS_HOST="$2"; shift 2;;
        --webhook-endpoint) WEBHOOK_ENDPOINT="$2"; shift 2;;
        --webhook-user-name) WEBHOOK_USER_NAME="$2"; shift 2;;
        --webhook-user-agent) WEBHOOK_USER_AGENT="$2"; shift 2;;
        --webhook-auth-token) WEBHOOK_AUTH_TOKEN="$2"; shift 2;;
        --prometheus-host) PROMETHEUS_HOST="$DEFAULT_PROMETHEUS_HOST"; shift 2;;
        --loki-host) LOKI_HOST="$2"; shift 2;;
        --tempo-host) TEMPO_HOST="$2"; shift 2;;
        --values-template) VALUES_TEMPLATE="$2"; shift 2;;
        --skip-event-exporter) SKIP_EVENT_EXPORTER=true; shift;;
        --skip-monitoring) SKIP_MONITORING=true; shift;;
        --skip-cost-analysis) SKIP_COST_ANALYSIS=true; shift;;
        --skip-webhook) SKIP_WEBHOOK=true; shift;;
        --skip-trivy) SKIP_TRIVY=true; shift;;
        --skip-kyverno) SKIP_KYVERNO=true; shift;;
        --dry-run) DRY_RUN=true; shift;;
        -h|--help) show_usage;;
        *)
            if [[ -z "$CLUSTER_NAME" ]]; then CLUSTER_NAME="$1"; shift
            elif [[ -z "$USERNAME" || "$USERNAME" == "${K8S_USERNAME:-admin-user}" ]]; then USERNAME="$1"; shift
            elif [[ -z "$WEBHOOK_ENDPOINT" || "$WEBHOOK_ENDPOINT" == "$DEFAULT_WEBHOOK_ENDPOINT" ]]; then WEBHOOK_ENDPOINT="$1"; shift
            else log_error "Unknown option or argument: $1"; show_usage; exit 1; fi;;
    esac
done

if [[ -z "$CLUSTER_NAME" ]]; then
    log_error "CLUSTER_NAME is required"
    show_usage
    exit 1
fi

### Sanitize Service Account Name
SA_NAME=$(echo "$USERNAME" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9.-]/-/g' | sed 's/^-*//;s/-*$//')
if [[ ! "$SA_NAME" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$ ]]; then
    log_error "Invalid service account name '$SA_NAME'. Must be a lowercase RFC 1123 subdomain."
    exit 1
fi
SECRET_NAME="${SA_NAME}-token"

### Helper Functions

check_already_installed() {
    local namespaces_to_check=(
        "greenops"
        "finops"
        "alloy"
        "kubesage-security"
        "kyverno"
    )

    for ns in "${namespaces_to_check[@]}"; do
        if kubectl get namespace "$ns" >/dev/null 2>&1; then
            log_warning "Namespace '$ns' already exists."
            log_error "Cannot override existing namespace. Exiting."
            exit 1
        fi
    done
}

check_prerequisites_helm_kubectl_commands() {
    for tool in kubectl helm envsubst curl base64; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            log_error "Missing required tool helm , envsubst, curl: $tool"
            exit 1
        fi
    done
}

determine_kubeconfig() {
    if [[ -n "$KUBE_CONFIG" && -f "$KUBE_CONFIG" ]]; then
        :
    elif [ -f "$RKE2_DEFAULT_CONFIG" ]; then
        KUBE_CONFIG="$RKE2_DEFAULT_CONFIG"
    elif [ -f "$K3S_DEFAULT_CONFIG" ]; then
        KUBE_CONFIG="$K3S_DEFAULT_CONFIG"
    elif [ -f "$HOME/.kube/config" ]; then
        KUBE_CONFIG="$HOME/.kube/config"
    else
        log_error "No config file found"
        exit 1
    fi

    SUDO=""
    if ! cat "$KUBE_CONFIG" >/dev/null 2>&1; then
        SUDO="sudo -E"
    fi
}

detect_k8s_distribution() {
    if [ -f "$RKE2_DEFAULT_CONFIG" ]; then
        echo "rke2"
    elif [ -f "$K3S_DEFAULT_CONFIG" ]; then
        echo "k3s"
    else
        local node_info=$($SUDO kubectl --kubeconfig="$KUBE_CONFIG" get nodes -o yaml 2>/dev/null)
        if echo "$node_info" | grep -q "rke2"; then echo "rke2"
        elif echo "$node_info" | grep -q "k3s"; then echo "k3s"
        else echo "standard"; fi
    fi
}

get_api_server_url() {
    local initial_url=$($SUDO kubectl --kubeconfig="$KUBE_CONFIG" config view --minify -o jsonpath='{.clusters[0].cluster.server}')
    if [[ "$initial_url" =~ /k8s/clusters/ ]]; then
        if [[ "$K8S_DISTRIBUTION" == "rke2" && -f "$RKE2_DEFAULT_CONFIG" ]]; then
            $SUDO cat "$RKE2_DEFAULT_CONFIG" | grep server: | awk '{print $2}' | head -n 1
        elif [[ "$K8S_DISTRIBUTION" == "k3s" && -f "$K3S_DEFAULT_CONFIG" ]]; then
            $SUDO cat "$K3S_DEFAULT_CONFIG" | grep server: | awk '{print $2}' | head -n 1
        else
            local master_ip=$($SUDO kubectl --kubeconfig="$KUBE_CONFIG" get nodes -l node-role.kubernetes.io/control-plane=true -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}' 2>/dev/null)
            if [[ -n "$master_ip" ]]; then echo "https://${master_ip}:6443"; else echo "$initial_url"; fi
        fi
    else
        if [[ "$initial_url" =~ 127.0.0.1 ]]; then
            local machine_ip=$(hostname -I | awk '{print $1}' 2>/dev/null || ip addr show | grep -oP 'inet \K[\d.]+' | grep -v '127.0.0.1' | head -n 1)
            if [[ -n "$machine_ip" ]]; then
                echo "${initial_url/127.0.0.1/$machine_ip}"
            else
                echo "$initial_url"
            fi
        else
            echo "$initial_url"
        fi
    fi
}

create_service_account_resources() {
    if ! $SUDO kubectl --kubeconfig="$KUBE_CONFIG" get namespace "$NAMESPACE" >/dev/null 2>&1; then
        $SUDO kubectl --kubeconfig="$KUBE_CONFIG" create namespace "$NAMESPACE"
    fi

    $SUDO kubectl --kubeconfig="$KUBE_CONFIG" apply -f - <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: $SA_NAME
  namespace: $NAMESPACE
EOF

    $SUDO kubectl --kubeconfig="$KUBE_CONFIG" apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: ${SA_NAME}-cluster-admin
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: ServiceAccount
  name: $SA_NAME
  namespace: $NAMESPACE
EOF

    $SUDO kubectl --kubeconfig="$KUBE_CONFIG" apply -f - <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: $SECRET_NAME
  namespace: $NAMESPACE
  annotations:
    kubernetes.io/service-account.name: $SA_NAME
type: kubernetes.io/service-account-token
EOF

    retries=0
    while [[ $retries -lt 60 ]]; do
        if $SUDO kubectl --kubeconfig="$KUBE_CONFIG" get secret "$SECRET_NAME" -n "$NAMESPACE" -o jsonpath='{.data.token}' | base64 -d | grep -q "eyJ"; then
            break
        fi
        sleep 2
        ((retries++))
    done

    SA_TOKEN=$($SUDO kubectl --kubeconfig="$KUBE_CONFIG" get secret "$SECRET_NAME" -n "$NAMESPACE" -o jsonpath='{.data.token}' | base64 -d 2>/dev/null || echo "")
    if [[ -z "$SA_TOKEN" ]]; then
        SA_TOKEN=$($SUDO kubectl --kubeconfig="$KUBE_CONFIG" create token "$SA_NAME" -n "$NAMESPACE" --duration=87600h 2>/dev/null || echo "")
    fi
    if [[ -z "$SA_TOKEN" ]]; then
        local secret_name=$($SUDO kubectl --kubeconfig="$KUBE_CONFIG" get serviceaccount "$SA_NAME" -n "$NAMESPACE" -o jsonpath='{.secrets[0].name}' 2>/dev/null || echo "")
        if [[ -n "$secret_name" ]]; then
            SA_TOKEN=$($SUDO kubectl --kubeconfig="$KUBE_CONFIG" get secret "$secret_name" -n "$NAMESPACE" -o jsonpath='{.data.token}' | base64 -d 2>/dev/null || echo "")
        fi
    fi
    if [[ -z "$SA_TOKEN" ]]; then log_error "Failed to retrieve token"; exit 1; fi
}

setup_new_kubeconfig() {
    NEW_KUBE_CONFIG="/tmp/new-kubeconfig.yaml"
    cat <<EOF > "$NEW_KUBE_CONFIG"
apiVersion: v1
kind: Config
clusters:
- name: cluster
  cluster:
    server: $API_SERVER_URL
    insecure-skip-tls-verify: true
users:
- name: $SA_NAME
  user:
    token: $SA_TOKEN
contexts:
- name: ${SA_NAME}-context
  context:
    cluster: cluster
    user: $SA_NAME
current-context: ${SA_NAME}-context
EOF
    chmod 600 "$NEW_KUBE_CONFIG"
    export KUBECONFIG="$NEW_KUBE_CONFIG"
}

install_values_template() {
    local BASE_URL="http://10.0.2.21"
    local FILE_NAME="values-template.yaml"
    if [ -f "$FILE_NAME" ]; then
        :
    elif curl --output /dev/null --silent --head --fail "$BASE_URL/$FILE_NAME"; then
        curl -O "$BASE_URL/$FILE_NAME"
    else
        log_error "$BASE_URL/$FILE_NAME not accessible"
        exit 1
    fi
}

render_values() {
    log_info "Rendering values..."

    if [ -z "$VALUES_TEMPLATE" ]; then
        log_error "VALUES_TEMPLATE environment variable is not set"
        exit 1
    fi

    if [ ! -f "$VALUES_TEMPLATE" ]; then
        log_error "Values template not found: $VALUES_TEMPLATE"
        exit 1
    fi
    if [ ! -r "$VALUES_TEMPLATE" ]; then
        log_error "Values template is not readable: $VALUES_TEMPLATE"
        exit 1
    fi

    local required_vars=("OS_USERNAME" "OS_PASSWORD" "OS_HOST" "SA_NAME" "WEBHOOK_USER_NAME" "CLUSTER_NAME" "WEBHOOK_ENDPOINT")
    for var in "${required_vars[@]}"; do
        if [ -z "${!var}" ]; then
            log_error "Required environment variable $var is not set"
            exit 1
        fi
    done

    export OS_USERNAME OS_PASSWORD OS_HOST USERNAME="$SA_NAME" WEBHOOK_ENDPOINT WEBHOOK_USERNAME="$WEBHOOK_USER_NAME" CLUSTER_NAME
    export PIPELINE_ID="${RANDOM}-$(date +%s)"
    export COMMIT_SHA="$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')"
    export BRANCH_USERNAME="$(git branch --show-current 2>/dev/null || echo 'unknown')"
    export DEPLOY_TIME="$(date -u '+%Y-%m-%dT%H:%M:%S%Z')"

    if envsubst < "$VALUES_TEMPLATE" > values.yml; then
        log_success "Rendered values.yml"
        if [ "$DRY_RUN" == "true" ]; then
            log_info "values.yml content:"
            cat values.yml
        fi
    else
        log_error "Failed to render values"
        exit 1
    fi

    if [ ! -s values.yml ]; then
        log_error "Rendered values.yml is empty or was not created"
        exit 1
    fi
}

deploy_event_exporter() {
    log_info "Deploying Kubernetes Event Exporter..."
    helm repo add bitnami https://charts.bitnami.com/bitnami >/dev/null 2>&1 || log_info "Bitnami repo already added"
    log_info "Updating Helm repositories..."
    if ! timeout 30s helm repo update >/dev/null 2>&1; then
        log_error "Failed to update Helm repositories or operation timed out"
        exit 1
    fi
    if [[ "$DRY_RUN" == "true" ]]; then
        log_warning "Dry run: Skipping event exporter deployment"
    else
        if timeout 300s helm upgrade --install kube-event-exporter bitnami/kubernetes-event-exporter \
            --version 3.0.2 --create-namespace -n "$NAMESPACE" -f values.yml --debug > /tmp/helm_event_exporter.log 2>&1; then
            sudo rm values.yml
            sudo rm values-template.yaml
        else
            log_error "Failed to deploy Event Exporter. Check /tmp/helm_event_exporter.log for details"
            cat /tmp/helm_event_exporter.log >&2
            exit 1
        fi
    fi
}

deploy_monitoring() {
    if [[ "$SKIP_MONITORING" == "true" ]]; then return; fi
    helm repo add grafana https://grafana.github.io/helm-charts >/dev/null 2>&1 || true
    helm repo update >/dev/null 2>&1
    if [[ "$DRY_RUN" == "true" ]]; then return; fi
    helm --kubeconfig="$KUBECONFIG" upgrade --install my-release grafana/k8s-monitoring --version ^1 \
        --set cluster.name="${CLUSTER_NAME}" \
        --set externalServices.prometheus.host="${PROMETHEUS_HOST}" \
        --set externalServices.prometheus.writeEndpoint=/api/v1/write \
        --set externalServices.prometheus.externalLabels.username="${SA_NAME}" \
        --set externalServices.loki.host="${LOKI_HOST}" \
        --set externalServices.tempo.host="${TEMPO_HOST}" \
        --set grafana.enabled=true > /dev/null 2>&1 || true
}

deploy_cost_analysis() {
    if [[ "$SKIP_COST_ANALYSIS" == "true" ]]; then return; fi
    helm repo add kepler https://sustainable-computing-io.github.io/kepler-helm-chart >/dev/null 2>&1 || true
    helm repo add opencost https://opencost.github.io/opencost-helm-chart >/dev/null 2>&1 || true
    helm repo add grafana https://grafana.github.io/helm-charts >/dev/null 2>&1 || true
    helm repo add prometheus-community https://prometheus-community.github.io/helm-charts >/dev/null 2>&1 || true
    helm repo update >/dev/null 2>&1
    if [[ "$DRY_RUN" == "true" ]]; then return; fi

    kubectl create ns greenops --dry-run=client -o yaml | kubectl apply -f -
    helm --kubeconfig="$KUBECONFIG" upgrade --install kepler kepler/kepler -n greenops > /dev/null 2>&1 || true

    kubectl create ns prometheus-system --dry-run=client -o yaml | kubectl apply -f -
    helm --kubeconfig="$KUBECONFIG" upgrade --install prometheus prometheus-community/prometheus \
        --namespace prometheus-system \
        --set prometheus-pushgateway.enabled=false \
        --set alertmanager.enabled=false \
        -f https://raw.githubusercontent.com/opencost/opencost/develop/kubernetes/prometheus/extraScrapeConfigs.yaml > /dev/null 2>&1 || true

    kubectl create ns finops --dry-run=client -o yaml | kubectl apply -f -
    helm --kubeconfig="$KUBECONFIG" upgrade --install opencost opencost/opencost -n finops > /dev/null 2>&1 || true
    kubectl patch deployment opencost -n finops --type='json' -p='[{"op": "replace", "path": "/spec/template/spec/containers/0/env", "value": [{"name": "PROMETHEUS_SERVER_ENDPOINT", "value": "'"$PROMETHEUS_HOST"'"}]}]' > /dev/null 2>&1 || true

    kubectl create ns alloy --dry-run=client -o yaml | kubectl apply -f -
    cat <<EOF > config.alloy
prometheus.scrape "opencost" {
  targets = [{"__address__" = "opencost.finops.svc.cluster.local:9003"}]
  scrape_interval = "1m"
  metrics_path = "/metrics"
  forward_to = [prometheus.remote_write.central.receiver]
}
prometheus.scrape "kepler" {
  targets = [{"__address__" = "kepler.greenops.svc.cluster.local:9102"}]
  scrape_interval = "1m"
  metrics_path = "/metrics"
  forward_to = [prometheus.remote_write.central.receiver]
}
prometheus.scrape "trivy_operator"{
  targets = [{"--address__" = "trivy-operator.kubesage-security.svc.cluster.local:80"}]
  scrape_interval = "1m"
  metrics_path = "/metrics"
  forward_to = [prometheus.remote_write.central.receiver]
}
prometheus.remote_write "central" {
  endpoint { url = "$PROMETHEUS_HOST/api/v1/write" }
  external_labels = { cluster = "$CLUSTER_NAME", username = "$SA_NAME" }
}
EOF
    kubectl create configmap --namespace alloy alloy-config --from-file=config.alloy=./config.alloy --dry-run=client -o yaml | kubectl apply -f -
    cat <<EOF > values.yaml
alloy:
  configMap:
    create: false
    name: alloy-config
    key: config.alloy
EOF
    helm --kubeconfig="$KUBECONFIG" upgrade --install alloy grafana/alloy -n alloy -f values.yaml > /dev/null 2>&1 || true
}

deploy_trivy() {
    if [[ "$SKIP_TRIVY" == "true" ]]; then return; fi
    helm repo add aquasecurity https://aquasecurity.github.io/helm-charts/ >/dev/null 2>&1 || true
    helm repo update >/dev/null 2>&1
    if [[ "$DRY_RUN" == "true" ]]; then return; fi
    kubectl create namespace kubesage-security --dry-run=client -o yaml | kubectl apply -f -
    helm --kubeconfig="$KUBECONFIG" upgrade --install trivy-operator aquasecurity/trivy-operator -n kubesage-security -f http://10.0.2.21/trivy-values.yaml > /dev/null 2>&1 || true
    kubectl rollout status deployment/trivy-operator -n kubesage-security --timeout=120s > /dev/null 2>&1 || true
}

deploy_kyverno() {
    if [[ "$SKIP_KYVERNO" == "true" ]]; then return; fi
    helm repo add kyverno https://kyverno.github.io/kyverno/ >/dev/null 2>&1 || true
    helm repo update >/dev/null 2>&1
    if [[ "$DRY_RUN" == "true" ]]; then return; fi
    helm --kubeconfig="$KUBECONFIG" upgrade --install kyverno kyverno/kyverno -n kyverno --create-namespace > /dev/null 2>&1 || true
}

send_webhook() {
    if [[ "$SKIP_WEBHOOK" == "true" ]]; then return; fi
    cat > webhook_payload.json <<EOF
{
  "cluster_name": "$CLUSTER_NAME",
  "server_url": "$API_SERVER_URL",
  "token": "$SA_TOKEN",
  "username": "$SA_NAME"
}
EOF
    if [[ "$DRY_RUN" == "true" ]]; then
        :
    elif curl -k -X POST "$WEBHOOK_ENDPOINT" \
        -H "Authorization: Bearer $WEBHOOK_AUTH_TOKEN" \
        -H "Content-Type: application/json" \
        -d @webhook_payload.json \
        --insecure --fail --show-error --silent > /dev/null 2>&1; then
        :
    else
        :
    fi
}

detect_k8s_distribution_step() {
    K8S_DISTRIBUTION=$(detect_k8s_distribution)
}

get_api_server_url_step() {
    API_SERVER_URL=$(get_api_server_url)
}

cleanup_temp_files() {
    rm -f config.alloy values.yaml webhook_payload.json /tmp/new-kubeconfig.yaml
}

show_credentials() {
    echo -e "\n--- Kubernetes Service Account Credentials ---"
    echo "API Server URL: $API_SERVER_URL"
    echo "Service Account Token: $SA_TOKEN"
}

main() {
    show_progress
    check_already_installed
    run_step check_prerequisites_helm_kubectl_commands
    run_step determine_kubeconfig
    run_step detect_k8s_distribution_step
    run_step get_api_server_url_step
    run_step create_service_account_resources
    run_step setup_new_kubeconfig
    run_step install_values_template
    run_step render_values
    run_step deploy_event_exporter
    run_step deploy_monitoring
    run_step deploy_cost_analysis
    run_step deploy_trivy
    run_step deploy_kyverno
    run_step send_webhook
    run_step cleanup_temp_files
    show_credentials

    echo -e "Onboarding Completed!."
}

main "$@"
