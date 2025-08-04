################################
# 1. NAMESPACES
################################
resource "kubernetes_namespace" "ingress_nginx" {
  metadata { name = "ingress-nginx" }
}

resource "kubernetes_namespace" "openebs" {
  metadata { name = "openebs" }
}

resource "kubernetes_namespace" "logging" {
  metadata { name = "logging" }
}

resource "kubernetes_namespace" "monitoring" {
  metadata { name = "monitoring" }
}

################################
# 2. INGRESS NGINX
################################
resource "helm_release" "ingress_nginx" {
  name       = "ingress-nginx"
  repository = "https://kubernetes.github.io/ingress-nginx"
  chart      = "ingress-nginx"
  namespace  = kubernetes_namespace.ingress_nginx.metadata[0].name
  version    = "4.10.1"
  values = [<<EOF
controller:
  service:
    type: NodePort
    nodePorts:
      http: 30080
      https: 30443
EOF
  ]
}

################################
# 3. OPENEBS
################################
resource "helm_release" "openebs" {
  depends_on = [helm_release.ingress_nginx]
  name       = "openebs"
  repository = "https://openebs.github.io/charts"
  chart      = "openebs"
  namespace  = kubernetes_namespace.openebs.metadata[0].name
  version    = "3.9.0"
  values = [<<EOF
ndm:
  enabled: false
localprovisioner:
  enabled: true
  basePath: "/var/openebs/local"
  storageClass:
    hostpath:
      name: "openebs-hostpath"
      isDefaultClass: true
      reclaimPolicy: Delete
      annotations:
        storageclass.kubernetes.io/is-default-class: "true"
EOF
  ]
}

################################
# 4. CERTIFICATE GENERATION
################################
# CA Certificate
resource "tls_private_key" "elastic_ca" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "tls_self_signed_cert" "elastic_ca" {
  private_key_pem = tls_private_key.elastic_ca.private_key_pem
  subject {
    common_name  = "elastic-ca"
    organization = "Elastic CA"
  }
  validity_period_hours = 8760
  is_ca_certificate     = true
  allowed_uses = [
    "key_encipherment",
    "digital_signature",
    "cert_signing",
  ]
}

# Elasticsearch Certificates
resource "tls_private_key" "elasticsearch" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_cert_request" "elasticsearch" {
  private_key_pem = tls_private_key.elasticsearch.private_key_pem
  subject {
    common_name  = "elasticsearch-master"
    organization = "Elastic"
  }
  dns_names = [
    "elasticsearch-master",
    "elasticsearch-master.logging",
    "elasticsearch-master.logging.svc",
    "elasticsearch-master.logging.svc.cluster.local",
    "localhost"
  ]
  ip_addresses = ["127.0.0.1"]
}

resource "tls_locally_signed_cert" "elasticsearch" {
  cert_request_pem      = tls_cert_request.elasticsearch.cert_request_pem
  ca_private_key_pem    = tls_private_key.elastic_ca.private_key_pem
  ca_cert_pem           = tls_self_signed_cert.elastic_ca.cert_pem
  validity_period_hours = 8760
  allowed_uses = [
    "key_encipherment",
    "digital_signature",
    "server_auth",
    "client_auth",
  ]
}

# Kibana Certificates
resource "tls_private_key" "kibana" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_cert_request" "kibana" {
  private_key_pem = tls_private_key.kibana.private_key_pem
  subject {
    common_name  = "kibana"
    organization = "Elastic"
  }
  dns_names = [
    "kibana",
    "kibana.logging",
    "kibana.logging.svc",
    "kibana.logging.svc.cluster.local"
  ]
}

resource "tls_locally_signed_cert" "kibana" {
  cert_request_pem      = tls_cert_request.kibana.cert_request_pem
  ca_private_key_pem    = tls_private_key.elastic_ca.private_key_pem
  ca_cert_pem           = tls_self_signed_cert.elastic_ca.cert_pem
  validity_period_hours = 8760
  allowed_uses = [
    "key_encipherment",
    "digital_signature",
    "server_auth",
    "client_auth",
  ]
}

# Filebeat Certificates
resource "tls_private_key" "filebeat" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_cert_request" "filebeat" {
  private_key_pem = tls_private_key.filebeat.private_key_pem
  subject {
    common_name  = "filebeat"
    organization = "Elastic"
  }
}

resource "tls_locally_signed_cert" "filebeat" {
  cert_request_pem      = tls_cert_request.filebeat.cert_request_pem
  ca_private_key_pem    = tls_private_key.elastic_ca.private_key_pem
  ca_cert_pem           = tls_self_signed_cert.elastic_ca.cert_pem
  validity_period_hours = 8760
  allowed_uses = [
    "key_encipherment",
    "digital_signature",
    "server_auth",
    "client_auth",
  ]
}

################################
# 5. SECRET CREATION
################################
# Elasticsearch specific certs
resource "kubernetes_secret" "elasticsearch_master_certs" {
  metadata {
    name      = "elasticsearch-master-certs"
    namespace = kubernetes_namespace.logging.metadata[0].name
  }
  data = {
    "ca.crt"  = tls_self_signed_cert.elastic_ca.cert_pem
    "tls.crt" = tls_locally_signed_cert.elasticsearch.cert_pem
    "tls.key" = tls_private_key.elasticsearch.private_key_pem
  }
}

# Shared certs for other components
resource "kubernetes_secret" "elastic_certificates" {
  metadata {
    name      = "elastic-certificates"
    namespace = kubernetes_namespace.logging.metadata[0].name
  }
  data = {
    "ca.crt"       = tls_self_signed_cert.elastic_ca.cert_pem
    "kibana.crt"   = tls_locally_signed_cert.kibana.cert_pem
    "kibana.key"   = tls_private_key.kibana.private_key_pem
    "filebeat.crt" = tls_locally_signed_cert.filebeat.cert_pem
    "filebeat.key" = tls_private_key.filebeat.private_key_pem
  }
}

# Credentials secret
resource "kubernetes_secret" "elasticsearch_credentials" {
  metadata {
    name      = "elasticsearch-master-credentials"
    namespace = kubernetes_namespace.logging.metadata[0].name
  }
  data = {
    "username" = "elastic"
    "password" = "CegthGegthGfhjkm1337"
  }
}

################################
# 6. ELASTICSEARCH
################################
resource "helm_release" "elasticsearch" {
  depends_on = [
    kubernetes_secret.elasticsearch_master_certs,
    kubernetes_secret.elasticsearch_credentials
  ]
  name       = "elasticsearch"
  repository = "https://helm.elastic.co"
  chart      = "elasticsearch"
  version    = "7.17.3"
  namespace  = kubernetes_namespace.logging.metadata[0].name

  set {
    name  = "clusterName"
    value = "elasticsearch"
  }

  set {
    name  = "nodeGroup"
    value = "master"
  }

  set {
    name  = "replicas"
    value = 1
  }

  set {
    name  = "security.enabled"
    value = "true"
  }

  set {
    name  = "security.elasticPassword"
    value = "CegthGegthGfhjkm1337"
  }

  set {
    name  = "resources.requests.memory"
    value = "1Gi"
  }
  set {
    name  = "resources.limits.memory"
    value = "2Gi"
  }
  set {
    name  = "resources.requests.cpu"
    value = "500m"
  }
  set {
    name  = "resources.limits.cpu"
    value = "1"
  }

  set {
    name  = "persistence.enabled"
    value = "true"
  }
  set {
    name  = "persistence.storageClass"
    value = "openebs-hostpath"
  }
  set {
    name  = "persistence.size"
    value = "30Gi"
  }
  set {
    name  = "volumeClaimTemplate.accessModes[0]"
    value = "ReadWriteOnce"
  }

  set {
    name  = "esJavaOpts"
    value = "-Xmx1g -Xms1g"
  }

  values = [<<EOF
secretMounts:
  - name: elasticsearch-master-certs
    secretName: elasticsearch-master-certs
    path: /usr/share/elasticsearch/config/certs

volumeMounts:
  - name: elasticsearch-master-certs
    mountPath: /usr/share/elasticsearch/config/certs
    readOnly: true
EOF
  ]
}

################################
# 7. KIBANA
################################
resource "helm_release" "kibana" {
  depends_on = [
    helm_release.elasticsearch,
    kubernetes_secret.elastic_certificates
  ]
  name       = "kibana"
  repository = "https://helm.elastic.co"
  chart      = "kibana"
  namespace  = kubernetes_namespace.logging.metadata[0].name
  version    = "8.5.1"

  # Force recreation if previous install failed
  force_update  = true
  recreate_pods = true

  values = [<<EOF
# Disable problematic hooks
hooks:
  enabled: false

# Configure proper token creation
createKibanaToken: false  # Disable automatic token creation
elasticsearch:
  hosts: ["https://elasticsearch-master:9200"]
  username: "elastic"
  password: "CegthGegthGfhjkm1337"
  ssl:
    verificationMode: "certificate"
    certificateAuthorities: ["/usr/share/kibana/config/certs/ca.crt"]

# Main configuration
server:
  ssl:
    enabled: true
    certificate: /usr/share/kibana/config/certs/kibana.crt
    key: /usr/share/kibana/config/certs/kibana.key

secretMounts:
  - name: elastic-certificates
    secretName: elastic-certificates
    path: /usr/share/kibana/config/certs

service:
  type: NodePort
  nodePort: 30601

resources:
  requests:
    cpu: 100m
    memory: 512Mi
  limits:
    cpu: 1000m
    memory: 1Gi
EOF
  ]
}

################################
# MANUAL TOKEN CREATION JOB
################################
resource "kubernetes_job" "create_kibana_token" {
  depends_on = [helm_release.kibana]
  metadata {
    name      = "create-kibana-token"
    namespace = kubernetes_namespace.logging.metadata[0].name
  }
  spec {
    template {
      metadata {}
      spec {
        container {
          name  = "token-creator"
          image = "docker.elastic.co/kibana/kibana:8.5.1"
          command = [
            "/usr/share/kibana/node/bin/node",
            "/usr/share/kibana/scripts/create-kibana-token.js",
            "--url=https://elasticsearch-master:9200",
            "--username=elastic",
            "--password=CegthGegthGfhjkm1337",
            "--ca-cert=/usr/share/kibana/config/certs/ca.crt"
          ]
          volume_mount {
            name       = "certs"
            mount_path = "/usr/share/kibana/config/certs"
            read_only  = true
          }
        }
        volume {
          name = "certs"
          secret {
            secret_name = "elastic-certificates"
          }
        }
        restart_policy = "Never"
      }
    }
    backoff_limit = 2
  }

  # Wait for Elasticsearch to be ready
  provisioner "local-exec" {
    command = <<EOT
      kubectl wait --namespace=${kubernetes_namespace.logging.metadata[0].name} \
        --for=condition=ready pod \
        -l app=elasticsearch-master \
        --timeout=300s
    EOT
  }
}

################################
# 8. LOGSTASH
################################
resource "kubernetes_service" "logstash" {
  metadata {
    name      = "logstash"
    namespace = kubernetes_namespace.logging.metadata[0].name
  }
  spec {
    selector = {
      app = "logstash"
    }
    port {
      port        = 5044
      target_port = 5044
      name        = "beats"
    }
  }
}

resource "helm_release" "logstash" {
  depends_on = [
    helm_release.elasticsearch,
    kubernetes_service.logstash,
    kubernetes_secret.elastic_certificates
  ]
  name       = "logstash"
  repository = "https://helm.elastic.co"
  chart      = "logstash"
  namespace  = kubernetes_namespace.logging.metadata[0].name
  version    = "8.5.1"

  values = [<<EOF
service:
  enabled: false

logstashPipeline:
  logstash.conf: |
    input {
      beats {
        port => 5044
        ssl => true
        ssl_certificate_authorities => ["/usr/share/logstash/certs/ca.crt"]
        ssl_certificate => "/usr/share/logstash/certs/logstash.crt"
        ssl_key => "/usr/share/logstash/certs/logstash.key"
      }
    }
    output {
      elasticsearch {
        hosts => ["https://elasticsearch-master:9200"]
        index => "logs"
        user => "elastic"
        password => "CegthGegthGfhjkm1337"
        ssl => true
        cacert => "/usr/share/logstash/certs/ca.crt"
      }
    }

secretMounts:
  - name: elastic-certificates
    secretName: elastic-certificates
    path: /usr/share/logstash/certs

extraVolumes:
  - name: elastic-certificates
    secret:
      secretName: elastic-certificates
      items:
        - key: ca.crt
          path: ca.crt
        - key: kibana.crt
          path: logstash.crt
        - key: kibana.key
          path: logstash.key

resources:
  requests:
    cpu: "200m"
    memory: "512Mi"
  limits:
    cpu: "500m"
    memory: "1Gi"
EOF
  ]
}

################################
# 9. FILEBEAT
################################
resource "helm_release" "filebeat" {
  depends_on = [
    helm_release.logstash,
    kubernetes_secret.elastic_certificates
  ]
  name       = "filebeat-logging"
  repository = "https://helm.elastic.co"
  chart      = "filebeat"
  namespace  = kubernetes_namespace.logging.metadata[0].name
  version    = "8.5.1"

  values = [<<EOF
filebeatConfig:
  filebeat.yml: |
    filebeat.inputs:
      - type: container
        paths:
          - /var/log/containers/*.log
        processors:
          - add_kubernetes_metadata:
              matchers:
                - logs_path:
                    logs_path: "/var/log/containers/"
    output.logstash:
      hosts: ["logstash.logging.svc.cluster.local:5044"]
      ssl:
        enabled: true
        certificate_authorities: ["/usr/share/filebeat/certs/ca.crt"]
        certificate: "/usr/share/filebeat/certs/filebeat.crt"
        key: "/usr/share/filebeat/certs/filebeat.key"

secretMounts:
  - name: elastic-certificates
    secretName: elastic-certificates
    path: /usr/share/filebeat/certs

resources:
  requests:
    cpu: "100m"
    memory: "100Mi"
  limits:
    cpu: "1000m"
    memory: "200Mi"
EOF
  ]
}

################################
# 10. JAEGER
################################
resource "helm_release" "jaeger" {
  depends_on = [helm_release.elasticsearch]
  name       = "jaeger"
  repository = "https://jaegertracing.github.io/helm-charts"
  chart      = "jaeger"
  namespace  = kubernetes_namespace.logging.metadata[0].name
  version    = "3.4.1"

  values = [<<EOF
provisionDataStore:
  cassandra: false
  elasticsearch: false

storage:
  type: elasticsearch
  elasticsearch:
    host: elasticsearch-master
    port: 9200
    scheme: http
    user: elastic
    password: "CegthGegthGfhjkm1337"
    tls:
      enabled: false

query:
  extraEnv:
    - name: SPAN_STORAGE_TYPE
      value: "elasticsearch"
    - name: ES_SERVER_URLS
      value: "http://elasticsearch-master:9200"
    - name: ES_USERNAME
      value: "elastic"
    - name: ES_PASSWORD
      value: "CegthGegthGfhjkm1337"
  extraInitContainers:
    - name: wait-for-es
      image: curlimages/curl
      command: ['sh', '-c', 'until curl -s -u elastic:CegthGegthGfhjkm1337 http://elasticsearch-master:9200 | grep -q "You Know, for Search"; do echo waiting for elasticsearch; sleep 10; done']

collector:
  extraEnv:
    - name: SPAN_STORAGE_TYPE
      value: "elasticsearch"
    - name: ES_SERVER_URLS
      value: "http://elasticsearch-master:9200"
    - name: ES_USERNAME
      value: "elastic"
    - name: ES_PASSWORD
      value: "CegthGegthGfhjkm1337"
  extraInitContainers:
    - name: wait-for-es
      image: curlimages/curl
      command: ['sh', '-c', 'until curl -s -u elastic:CegthGegthGfhjkm1337 http://elasticsearch-master:9200 | grep -q "You Know, for Search"; do echo waiting for elasticsearch; sleep 10; done']
EOF
  ]
}

################################
# 11. PROMETHEUS STACK
################################
resource "helm_release" "kube_prometheus_stack" {
  depends_on = [helm_release.elasticsearch]
  name       = "kube-prometheus"
  repository = "https://prometheus-community.github.io/helm-charts"
  chart      = "kube-prometheus-stack"
  namespace  = kubernetes_namespace.monitoring.metadata[0].name
  version    = "75.15.1"
  values = [<<EOF
prometheus:
  prometheusSpec:
    retention: 2d
    storageSpec:
      volumeClaimTemplate:
        spec:
          storageClassName: "openebs-hostpath"
          accessModes: ["ReadWriteOnce"]
          resources:
            requests:
              storage: 2Gi
    resources:
      requests:
        cpu: 200m
        memory: 512Mi
      limits:
        cpu: 500m
        memory: 1Gi

grafana:
  adminPassword: "admin"
  service:
    type: NodePort
    nodePort: 30602
  resources:
    requests:
      cpu: 100m
      memory: 256Mi
    limits:
      cpu: 300m
      memory: 512Mi

alertmanager:
  alertmanagerSpec:
    storage:
      volumeClaimTemplate:
        spec:
          storageClassName: "openebs-hostpath"
          accessModes: ["ReadWriteOnce"]
          resources:
            requests:
              storage: 1Gi
    resources:
      requests:
        cpu: 100m
        memory: 128Mi
      limits:
        cpu: 200m
        memory: 256Mi
EOF
  ]
}
