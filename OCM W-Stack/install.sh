#!/bin/bash

set -ex

NAMESPACE=$1
DOMAIN=$2

if [ -z "$DOMAIN" ]; then
    echo "Error: DOMAIN parameter is not set"
    exit 1
fi

if [ -z "$NAMESPACE" ]; then
    echo "Error: NAMESPACE parameter is not set"
    exit 1
fi

# Create target namespace if it doesn't exist
if ! kubectl get namespace "${NAMESPACE}" &> /dev/null; then
    echo "Creating namespace ${NAMESPACE}"
    kubectl create namespace "${NAMESPACE}"
fi

sudo apt update

if ! openssl version &> /dev/null; then
    # install openssl if missing
    sudo apt-get install openssl
fi

if ! git version &> /dev/null; then
    # install git if missing
    sudo apt-get install git
fi

if ! helm version &> /dev/null; then 
    # install helm if missing
    sudo apt-get install helm
fi

sudo snap install cqlsh

helm repo add jetstack https://charts.jetstack.io --force-update

helm repo add nats https://nats-io.github.io/k8s/helm/charts/

helm repo add hashicorp https://helm.releases.hashicorp.com/

helm repo add k8ssandra https://helm.k8ssandra.io/stable

helm repo add codecentric https://codecentric.github.io/helm-charts

helm repo add cnpg https://cloudnative-pg.github.io/charts

helm repo update

if ! kubectl get namespace "cert-manager" &> /dev/null; then
    echo "############### Install Cert Manager"
    helm dependency build ./Cert-Manager; helm install cert-manager ./Cert-Manager  --create-namespace --namespace cert-manager
    helm dependency build ./Cluster-Issuer; helm install cluster-issuer ./Cluster-Issuer  --create-namespace --namespace cert-manager --set email=$1

fi 

if ! kubectl get namespace "cassandra" &> /dev/null; then

    kubectl create namespace cassandra

    CASSANDRA_NAMESPACE="cassandra"

    # Install k8ssandra-operator
    helm install k8ssandra-operator k8ssandra/k8ssandra-operator -n cassandra

    echo "Waiting for k8ssandra-operator to be ready..."
    kubectl wait --for=condition=available deployment/k8ssandra-operator -n cassandra --timeout=120s

    # Generate password for cassandra
    CASSANDRA_PASSWORD=$(openssl rand -hex 16)

    # Create the superuser secret
    kubectl create secret generic cassandra-superuser -n cassandra \
        --from-literal=username=cassandra \
        --from-literal=password=$CASSANDRA_PASSWORD
    
    # Create K8ssandraCluster resource
    kubectl apply -n cassandra -f - <<EOF
apiVersion: k8ssandra.io/v1alpha1
kind: K8ssandraCluster
metadata:
  name: cassandra
spec:
  cassandra:
    serverVersion: "4.1.0"
    superuserSecretRef:
      name: cassandra-superuser
    datacenters:
      - metadata:
          name: dc1
        size: 1
        storageConfig:
          cassandraDataVolumeClaimSpec:
            storageClassName: local-path
            accessModes:
              - ReadWriteOnce
            resources:
              requests:
                storage: 8Gi
        config:
          jvmOptions:
            heapSize: 512M
EOF

    echo "Waiting for cassandra cluster to be ready..."
    kubectl wait --for=condition=Running k8ssandracluster/cassandra -n cassandra --timeout=600s

    # Copy password to target namespace
    kubectl create secret generic "cassandra" -n ${NAMESPACE} \
        --from-literal=cassandra-password=$CASSANDRA_PASSWORD

    echo "Wait for cassandra to be finished"

    USERNAME="cassandra"
    PASSWORD=$CASSANDRA_PASSWORD

    echo "Versuche, eine Verbindung zu Cassandra herzustellen..."

    # Schleife, um Verbindung zu versuchen
    while true; do

        kubectl port-forward svc/cassandra-dc1-service 9042:9042 -n cassandra &
        PID=$!

        echo $PID

        # Wait for port-forward to establish
        sleep 3

        # Überprüfen ob cqlsh erfolgreich eine Verbindung herstellen kann
        if cqlsh -u $USERNAME -p $PASSWORD -e "SHOW HOST;" &> /dev/null; then
            echo "Erfolgreich mit Cassandra verbunden!"
        else
            echo "Verbindung fehlgeschlagen. Versuche es in 5 Sekunden erneut..."
            kill $PID 2>/dev/null || true
            sleep 5
            continue
        fi

        curl https://gitlab.eclipse.org/eclipse/xfsc/organisational-credential-manager-w-stack/storage-service/-/raw/main/scripts/cql/initialize.cql?ref_type=heads > storage.cql
        curl https://gitlab.eclipse.org/eclipse/xfsc/organisational-credential-manager-w-stack/credential-verification-service/-/raw/main/scripts/cql/initialize.cql?ref_type=heads > verification.cql
        curl https://gitlab.eclipse.org/eclipse/xfsc/organisational-credential-manager-w-stack/credential-retrieval-service/-/raw/main/scripts/cql/initialize.cql?ref_type=heads > retrieval.cql

        cqlsh -u $USERNAME -p $PASSWORD -f ./retrieval.cql
        cqlsh -u $USERNAME -p $PASSWORD -f ./storage.cql
        cqlsh -u $USERNAME -p $PASSWORD -f ./verification.cql

        kill $PID
        break;
    done
fi 

if ! kubectl get namespace "nats" &> /dev/null; then

    helm dependency build "./Nats Chart"; helm install nats "./Nats Chart" --create-namespace --namespace nats
fi 


if ! kubectl get namespace "keycloak" &> /dev/null; then
    echo "########### Install Keycloak#########"

    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
      -keyout tls.key \
      -out tls.crt \
      -subj "/CN=auth-cloud-wallet.${DOMAIN}/O=yourorganization"

    kubectl create namespace keycloak

    kubectl create secret tls xfsc-wildcard \
      --cert=tls.crt \
      --key=tls.key \
      --namespace keycloak

    # Create Keycloak database and user in CloudNativePG
    KC_DB_USER="xc_keycloak"
    KC_DB_PASSWORD=$(openssl rand -hex 16)
    KC_DB_NAME="xfsc_keycloak"
    KC_ADMIN_USER="admin"
    KC_ADMIN_PASSWORD=$(openssl rand -hex 16)

    if ! kubectl get namespace "postgres" &> /dev/null; then
      kubectl create namespace postgres
    fi

    kubectl exec -it postgres-1 -n postgres -- psql -U postgres -c "CREATE USER $KC_DB_USER WITH PASSWORD '$KC_DB_PASSWORD';"
    kubectl exec -it postgres-1 -n postgres -- psql -U postgres -c "CREATE DATABASE $KC_DB_NAME OWNER $KC_DB_USER;"


    # Create Keycloak secrets
    kubectl create secret generic keycloak-init-secrets -n keycloak \
      --from-literal=username=$KC_ADMIN_USER \
      --from-literal=admin-password=$KC_ADMIN_PASSWORD \
      --from-literal=password=$KC_DB_PASSWORD

    helm dependency build "./Keycloak"

    # Create temp values file with domain substitution
    sed "s/DOMAIN/${DOMAIN}/g" ./Keycloak/values.yaml > /tmp/keycloak-values.yaml

    helm install keycloak "./Keycloak" --namespace keycloak -f /tmp/keycloak-values.yaml
fi

if ! kubectl get namespace "vault" &> /dev/null; then

    echo "######### Install Vault"

    helm dependency build "./Vault";helm install vault "./Vault" --create-namespace --namespace vault
    sleep 10
      VAULT_NAMESPACE="vault"
      VAULT_POD=$(kubectl get pods -n ${VAULT_NAMESPACE} -l app.kubernetes.io/name=vault -o jsonpath="{.items[0].metadata.name}")
      VAULT_PORT=8200
      LOCAL_PORT=8200
      VAULT_TOKEN="root"

      # Starte kubectl port-forward im Hintergrund
      echo "Starte kubectl port-forward zum Vault-Pod..."
      # Loop zur Überprüfung der Vault-Verbindung
      while true; do

          kubectl port-forward -n ${VAULT_NAMESPACE} $VAULT_POD $LOCAL_PORT:$VAULT_PORT &

          PID=$!

          echo $PID
          # Überprüfe, ob der Vault-Server erreichbar ist
          if curl --silent --fail --output /dev/null "http://127.0.0.1:$LOCAL_PORT/v1/sys/health"; then
              echo "Erfolgreich mit Vault verbunden."
              break
          else
              echo "Warte auf Vault-Verbindung..."
              sleep 2  # Warte 2 Sekunden, bevor du es erneut versuchst
              continue
          fi
          kill $PID
          break
      done

     curl --header "X-Vault-Token: $VAULT_TOKEN" --request POST --data '{"type":"transit"}' http://127.0.0.1:8200/v1/sys/mounts/tenant_space
     curl --header "X-Vault-Token: $VAULT_TOKEN" --request POST --data '{"type":"ed25519"}' http://127.0.0.1:8200/v1/tenant_space/keys/signerkey
     curl --header "X-Vault-Token: $VAULT_TOKEN" --request POST --data '{"type":"ecdsa-p256"}' http://127.0.0.1:8200/v1/tenant_space/keys/eckey 

      # Beende das Port-Forwarding
      kill %1


fi 

# PostgreSQL-Admin-Benutzer und Passwort (falls nötig)
DB_ADMIN_USER="postgres"
DB_HOST=localhost


if ! kubectl get namespace "cnpg-system" &> /dev/null; then
    echo "######### Install CloudNativePG Operator"
    helm install cnpg cnpg/cloudnative-pg --namespace cnpg-system --create-namespace

    echo "Waiting for CloudNativePG operator to be ready..."
    kubectl wait --for=condition=available deployment/cnpg-cloudnative-pg -n cnpg-system --timeout=120s
fi

if ! kubectl get namespace "postgres" &> /dev/null; then
    echo "######### Install Postgres Cluster"
    kubectl create namespace postgres

    # Generate superuser password
    POSTGRES_PASSWORD=$(openssl rand -hex 16)

    # Create superuser secret
    kubectl create secret generic postgres-superuser -n postgres \
        --from-literal=username=postgres \
        --from-literal=password=$POSTGRES_PASSWORD

    # Create PostgreSQL cluster
    kubectl apply -n postgres -f - <<EOF
apiVersion: postgresql.cnpg.io/v1
kind: Cluster
metadata:
  name: postgres
spec:
  instances: 1
  imageName: ghcr.io/cloudnative-pg/postgresql:16.2
  bootstrap:
    initdb:
      database: postgres
      owner: postgres
      secret:
        name: postgres-superuser
  storage:
    size: 8Gi
  superuserSecret:
    name: postgres-superuser
EOF

    echo "Waiting for postgres cluster to be ready..."
    kubectl wait --for=condition=Ready cluster/postgres -n postgres --timeout=300s

    echo "Waiting for postgres pod to be ready..."
    sleep 10
    kubectl wait --for=condition=ready pod/postgres-1 -n postgres --timeout=300s

   kubectl delete secret statuslist-db-secret -n ${NAMESPACE} || echo "No statuslist-db-secret to delete"
   kubectl delete secret wellknown-db-secret -n ${NAMESPACE} || echo "No wellknown-db-secret to delete"

    while true; do
      kubectl exec -it postgres-1 -n postgres -- psql -U postgres -c 'SELECT 1'

      if [ $? -eq 0 ]; then
            echo "Erfolgreich mit Postgres verbunden!"
      else
            echo "Verbindung fehlgeschlagen. Versuche es in 5 Sekunden erneut..."
            sleep 5
            continue
      fi
      break
    done
fi

POSTGRES_PASSWORD=$(kubectl get secret --namespace postgres postgres-superuser -o jsonpath="{.data.password}" | base64 -d)

if ! kubectl get secret "wellknown-db-secret" -n "${NAMESPACE}" > /dev/null 2>&1; then

    DB_WELLKNOWN_USER="wellknown"
    DB_WELLKNOWN_PASSWORD=$(openssl rand -hex 32)
    DB_WELLKNOWN_NAME="wellknown"

    kubectl exec -it postgres-1 -n postgres -- psql -U postgres -c "CREATE USER $DB_WELLKNOWN_USER WITH PASSWORD '$DB_WELLKNOWN_PASSWORD';"
    kubectl exec -it postgres-1 -n postgres -- psql -U postgres -c "CREATE DATABASE $DB_WELLKNOWN_NAME OWNER $DB_WELLKNOWN_USER;"

    kubectl create secret generic wellknown-db-secret -n ${NAMESPACE} \
    --from-literal=postgresql-username=wellknown \
    --from-literal=postgresql-password=$DB_WELLKNOWN_PASSWORD

fi

if ! kubectl get secret "statuslist-db-secret" -n "${NAMESPACE}" > /dev/null 2>&1; then

    DB_STATUS_USER="statuslist"
    DB_STATUS_NAME="status"
    DB_STATUS_PASSWORD=$(openssl rand -hex 32)

    kubectl exec -it postgres-1 -n postgres -- psql -U postgres -c "CREATE USER $DB_STATUS_USER WITH PASSWORD '$DB_STATUS_PASSWORD';"
    kubectl exec -it postgres-1 -n postgres -- psql -U postgres -c "CREATE DATABASE $DB_STATUS_NAME OWNER $DB_STATUS_USER;"

    kubectl create secret generic statuslist-db-secret -n ${NAMESPACE} \
    --from-literal=postgresql-username=statuslist \
    --from-literal=postgresql-password=$DB_STATUS_PASSWORD
fi




echo "######### Install Universalresolver" 

helm dependency build "./Universal Resolver"
helm install universal-resolver "./Universal Resolver" --namespace ${NAMESPACE}



echo "####### Install Services"


openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
-keyout tls.key \
-out tls.crt \
-subj "/CN=cloud-wallet.${DOMAIN}/O=yourorganization"

if ! kubectl get service "pre-authorization-bridge-service" &> /dev/null; then

      echo "####### Install Pre Auth Bridge Client"

      ADMIN_SECRET_NAMESPACE="keycloak"   # Namespace für das Admin-Secret
      ADMIN_SECRET_NAME=" keycloak-init-secrets"  # Name des Kubernetes-Secrets für Admin
      NEW_CLIENT_SECRET_NAME="preauthbridge-oauth"  # Name des neuen Kubernetes-Secrets für den Client
      KEYCLOAK_URL="https://auth-cloud-wallet.${DOMAIN}"  # Keycloak-URL
      REALM="master"  # Keycloak-Realm
      NEW_CLIENT_ID="bridge"  # Neue Client-ID
      REDIRECT_URI="http://localhost"  # Redirect-URI

      ADMIN_USERNAME=$(kubectl get secret $ADMIN_SECRET_NAME -n $ADMIN_SECRET_NAMESPACE -o jsonpath='{.data.username}' | base64 --decode)
      ADMIN_PASSWORD=$(kubectl get secret $ADMIN_SECRET_NAME -n $ADMIN_SECRET_NAMESPACE -o jsonpath='{.data.admin-password}' | base64 --decode)

      ACCESS_TOKEN=$(curl -s -X POST "$KEYCLOAK_URL/realms/$REALM/protocol/openid-connect/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=password" \
        -d "client_id=admin-cli" \
        -d "username=$ADMIN_USERNAME" \
        -d "password=$ADMIN_PASSWORD" \
        | jq -r '.access_token')
      echo $ACCESS_TOKEN
      # Überprüfe, ob das Access Token erfolgreich geholt wurde
      if [ -z "$ACCESS_TOKEN" ]; then
        echo "Fehler: Konnte kein Access Token erhalten."
        exit 1
      fi

      CLIENT_EXISTS=$(curl -s -X GET "$KEYCLOAK_URL/admin/realms/$REALM/clients" \
      -H "Authorization: Bearer $ACCESS_TOKEN" \
      -H "Content-Type: application/json" | jq --arg CLIENT_ID "$NEW_CLIENT_ID" '.[] | select(.clientId == $CLIENT_ID) | .id' | tr -d '"')

      if [ -n "$CLIENT_EXISTS" ]; then
        echo "Der Client '$NEW_CLIENT_ID' existiert bereits mit der ID: $CLIENT_EXISTS"
        URL="$KEYCLOAK_URL/admin/realms/$REALM/clients/$CLIENT_EXISTS"
        echo $URL
        curl -X DELETE $URL \
        -H "Authorization: Bearer $ACCESS_TOKEN"
      fi
    

      NEW_CLIENT_SECRET=$(openssl rand -hex 32)

      # Erstelle den neuen Client in Keycloak
      RESPONSE=$(curl -s -X POST "$KEYCLOAK_URL/admin/realms/$REALM/clients" \
        -H "Authorization: Bearer $ACCESS_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{
              \"clientId\": \"$NEW_CLIENT_ID\",
              \"enabled\": true,
              \"clientAuthenticatorType\": \"client-secret\",
              \"secret\": \"$NEW_CLIENT_SECRET\",
              \"redirectUris\": [\"$REDIRECT_URI\"],
              \"standardFlowEnabled\": false,
              \"directAccessGrantsEnabled\": false,
              \"serviceAccountsEnabled\": true,
              \"authorizationServicesEnabled\": false
            }")

      # Überprüfe, ob der Client erfolgreich erstellt wurde
      if echo "$RESPONSE" | grep -q "error"; then
        echo "Fehler beim Erstellen des Clients: $RESPONSE"
        exit 1
      fi

      # Hole die ID des erstellten Clients
      CLIENT_UUID=$(curl -s -X GET "$KEYCLOAK_URL/admin/realms/$REALM/clients" \
        -H "Authorization: Bearer $ACCESS_TOKEN" \
        -H "Content-Type: application/json" \
        | jq -r ".[] | select(.clientId == \"$NEW_CLIENT_ID\") | .id")

      if [ -z "$CLIENT_UUID" ]; then
        echo "Fehler: Konnte die Client-ID nicht abrufen."
        exit 1
      fi
 
      # Schreibe Client-ID und Secret in ein neues Kubernetes-Secret im separaten Namespace für den Client
      kubectl create secret generic $NEW_CLIENT_SECRET_NAME -n ${NAMESPACE} \
        --from-literal=id=$NEW_CLIENT_ID \
        --from-literal=secret=$NEW_CLIENT_SECRET

      echo "######## Install Redis"

      REDISPW=$(openssl rand -hex 32)

      kubectl create secret generic "preauthbridge-redis" -n ${NAMESPACE} \
        --from-literal=redis-user=default \
        --from-literal=redis-password=$REDISPW

      # Deploy Redis with official image
      kubectl apply -n ${NAMESPACE} -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: redis-master
spec:
  replicas: 1
  selector:
    matchLabels:
      app: redis
  template:
    metadata:
      labels:
        app: redis
    spec:
      containers:
        - name: redis
          image: docker.io/redis:7
          ports:
            - containerPort: 6379
          command: ["/bin/sh", "-c"]
          args: ["redis-server --requirepass \$REDIS_PASSWORD"]
          env:
            - name: REDIS_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: preauthbridge-redis
                  key: redis-password
          resources:
            requests:
              memory: "128Mi"
              cpu: "100m"
            limits:
              memory: "256Mi"
              cpu: "250m"
---
apiVersion: v1
kind: Service
metadata:
  name: redis-master
spec:
  selector:
    app: redis
  ports:
    - port: 6379
      targetPort: 6379
EOF

      echo "Waiting for Redis to be ready..."
      kubectl wait --for=condition=available deployment/redis-master -n ${NAMESPACE} --timeout=120s

      kubectl create secret tls xfsc-wildcard \
        --cert=tls.crt \
        --key=tls.key \
        --namespace ${NAMESPACE}

      helm dependency build "./Pre Authorization Bridge Chart"
      helm install preauthbridge "./Pre Authorization Bridge Chart" -n ${NAMESPACE} \
        --set "pre-authorization-bridge.ingress.hosts[0].host=cloud-wallet.${DOMAIN}" \
        --set "pre-authorization-bridge.ingress.tls[0].hosts[0]=cloud-wallet.${DOMAIN}" \
        --set "pre-authorization-bridge.config.nats.url=nats://nats.nats.svc.cluster.local:4222" \
        --set "pre-authorization-bridge.config.database.hosts=redis-master.${NAMESPACE}.svc.cluster.local:6379" \
        --set "pre-authorization-bridge.config.oAuth.serverUrl=https://auth-cloud-wallet.${DOMAIN}/realms/master/protocol/openid-connect/token" \
        --set "pre-authorization-bridge.config.wellKnown.issuer=https://cloud-wallet.${DOMAIN}" \
        --set "pre-authorization-bridge.config.wellKnown.token_endpoint=https://cloud-wallet.${DOMAIN}/token"

fi

echo "######### Install TSA Stuff" 

helm dependency build "./Policy Chart"
helm install policy-service "./Policy Chart" --namespace ${NAMESPACE} \
  --set "policy.policy.nats.url=nats://nats.nats.svc.cluster.local:4222" \
  --set "policy.ingress.frontendDomain=cloud-wallet.${DOMAIN}"

rm -rf signer
rm -rf sd-jwt-service
git clone https://gitlab.eclipse.org/eclipse/xfsc/tsa/signer.git 
git clone https://gitlab.eclipse.org/eclipse/xfsc/common-services/sd-jwt-service.git

helm dependency build "./signer/deployment/helm"
helm install signer "./signer/deployment/helm" --namespace ${NAMESPACE} \
  --set "signer.vault.addr=http://vault.vault.svc.cluster.local:8200" \
  --set "signer.nats.natsHost=nats://nats.nats.svc.cluster.local:4222" \
  --set "signer.sdJwt.url=http://sd-jwt-service.${NAMESPACE}.svc.cluster.local:3000" \
  --set "signer.env[0].value=http://sd-jwt-service.${NAMESPACE}.svc.cluster.local:3000" \
  --set "signer.env[1].value=http://vault.vault.svc.cluster.local:8200" \
  --set "signer.env[3].value=nats://nats.nats.svc.cluster.local:4222" \
  --set "signer.env[4].value=nats://nats.nats.svc.cluster.local:4222" \
  --set "signer.env[6].value=https://vault.vault.svc:8200"

helm dependency build "./sd-jwt-service/deployment/helm"
helm install sd-jwt "./sd-jwt-service/deployment/helm" --namespace ${NAMESPACE} \
  --set "sd-jwt-service.config.signUrl=http://signer.${NAMESPACE}.svc.cluster.local:8080/v1/sign"

kubectl create secret generic vault -n ${NAMESPACE} \
  --from-literal=token=test

kubectl create secret tls xfsc-wildcard \
  --cert=tls.crt \
  --key=tls.key \
  --namespace ${NAMESPACE}

echo "###################Install Well Known Routes"

helm dependency build "./Well Known Ingress Rules"
helm install well-known-rules "./Well Known Ingress Rules" -n ${NAMESPACE} \
  --set "ingress.hostname=cloud-wallet.${DOMAIN}"

helm dependency build "./Well Known Chart"
helm install well-known "./Well Known Chart" -n ${NAMESPACE} \
  --set "well-known-service.ingress.hosts[0].host=cloud-wallet.${DOMAIN}" \
  --set "well-known-service.ingress.tls[0].hosts[0]=cloud-wallet.${DOMAIN}" \
  --set "well-known-service.config.postgres.host=postgres-rw.postgres.svc.cluster.local" \
  --set "well-known-service.config.nats.url=nats.nats.svc.cluster.local:4222" \
  --set "well-known-service.config.issuer=cloud-wallet.${DOMAIN}"

helm dependency build "./Didcomm"
helm install didcomm-connector "./Didcomm" -n ${NAMESPACE} \
  --set "didcomm-connector.ingress.hosts[0].host=cloud-wallet.${DOMAIN}" \
  --set "didcomm-connector.ingress.tls[0].hosts[0]=cloud-wallet.${DOMAIN}" \
  --set "didcomm-connector.config.url=https://cloud-wallet.${DOMAIN}/api/didcomm" \
  --set "didcomm-connector.config.didcomm.resolverUrl=http://universal-resolver-service.${NAMESPACE}.svc.cluster.local:8080" \
  --set "didcomm-connector.config.messaging.nats.url=nats://nats.nats.svc.cluster.local:4222" \
  --set "didcomm-connector.config.database.host=cassandra-dc1-service.cassandra.svc.cluster.local:9042"

helm dependency build "./Credential Issuance"
helm install credential-issuance "./Credential Issuance" -n ${NAMESPACE} \
  --set "issuance-service.ingress.hosts[0].host=cloud-wallet.${DOMAIN}" \
  --set "issuance-service.ingress.tls[0].hosts[0]=cloud-wallet.${DOMAIN}" \
  --set "issuance-service.config.jwksUrl=https://auth-cloud-wallet.${DOMAIN}/realms/master/protocol/openid-connect/certs" \
  --set "issuance-service.config.audience=https://cloud-wallet.${DOMAIN}" \
  --set "issuance-service.config.nats.url=nats://nats.nats.svc.cluster.local:4222"

helm dependency build "./Credential Retrieval"
helm install credential-retrieval "./Credential Retrieval" -n ${NAMESPACE} \
  --set "credential-retrieval-service.ingress.hosts[0].host=cloud-wallet.${DOMAIN}" \
  --set "credential-retrieval-service.ingress.tls[0].hosts[0]=cloud-wallet.${DOMAIN}" \
  --set "credential-retrieval-service.config.nats.url=nats://nats.nats.svc.cluster.local:4222" \
  --set "credential-retrieval-service.config.cassandra.hosts=cassandra-dc1-service.cassandra.svc.cluster.local:9042"

echo "Create a signing key for credential verification service"
openssl ecparam -genkey -name prime256v1 -noout -out signing_key.pem
kubectl create secret -n ${NAMESPACE} generic signing --from-file=signing-key=signing_key.pem

helm dependency build "./Credential Verification Service Chart"
helm install credential-verification "./Credential Verification Service Chart" -n ${NAMESPACE} \
  --set "credential-verification-service.ingress.annotations.nginx\.ingress\.kubernetes\.io/configuration-snippet=proxy_set_header X-DID did:web:cloud-wallet.${DOMAIN};\nproxy_set_header X-NAMESPACE tenant_space;\nproxy_set_header X-KEY eckey;" \
  --set "credential-verification-service.ingress.hosts[0].host=cloud-wallet.${DOMAIN}" \
  --set "credential-verification-service.ingress.tls[0].hosts[0]=cloud-wallet.${DOMAIN}" \
  --set "credential-verification-service.config.cassandra.cassandraHosts=cassandra-dc1-service.cassandra.svc.cluster.local" \
  --set "credential-verification-service.config.didResolver=http://universal-resolver-service.${NAMESPACE}.svc.cluster.local:8080" \
  --set "credential-verification-service.config.externalPresentation.authorizeEndpoint=credential-verification-service.${NAMESPACE}.svc.cluster.local:8080/v1/tenants/tenant_space/presentation/" \
  --set "credential-verification-service.config.signerService.presentationVerifyUrl=http://signer.${NAMESPACE}.svc.cluster.local:8080/v1/presentation/verify" \
  --set "credential-verification-service.config.signerService.presentationSignUrl=http://signer.${NAMESPACE}.svc.cluster.local:8080/v1/presentation/proof" \
  --set "credential-verification-service.config.messaging.nats.url=nats.nats.svc.cluster.local:4222"

helm dependency build "./Storage Service"
helm install storage-service "./Storage Service" -n ${NAMESPACE} \
  --set "storage-service.ingress.tls[0].hosts[0]=cloud-wallet.${DOMAIN}" \
  --set "storage-service.config.cassandra.hosts=cassandra-dc1-service.cassandra.svc.cluster.local:9042" \
  --set "storage-service.config.crypto.namespace=${NAMESPACE}" \
  --set "storage-service.config.messaging.host=nats://nats.nats.svc.cluster.local:4222" \
  --set "storage-service.config.vault.address=http://vault.vault.svc.cluster.local:8200"

helm dependency build "./Status List Service Chart"
helm install statuslist-service "./Status List Service Chart" -n ${NAMESPACE} \
  --set "status-list-service.ingress.annotations.nginx\.ingress\.kubernetes\.io/configuration-snippet=proxy_set_header X-DID did:web:cloud-wallet.${DOMAIN};\nproxy_set_header X-NAMESPACE tenant_space;\nproxy_set_header X-KEY signerkey;\nproxy_set_header X-GROUP \"\";\nproxy_set_header X-HOST cloud-wallet.${DOMAIN};\nproxy_set_header X-TYPE StatusList2021;" \
  --set "status-list-service.ingress.hosts[0].host=cloud-wallet.${DOMAIN}" \
  --set "status-list-service.ingress.tls[0].hosts[0]=cloud-wallet.${DOMAIN}" \
  --set "status-list-service.config.messaging.nats.url=http://nats.nats.svc.cluster.local:4222" \
  --set "status-list-service.config.database.host=postgres-rw.postgres.svc.cluster.local"

helm dependency build "./Dummy Content Signer"
helm install dummy-contentsigner "./Dummy Content Signer" -n ${NAMESPACE} \
  --set "dummycontentsigner.config.origin=https://cloud-wallet.${DOMAIN}" \
  --set "dummycontentsigner.config.credential_issuer=https://cloud-wallet.${DOMAIN}" \
  --set "dummycontentsigner.config.authorization_server[0]=https://cloud-wallet.${DOMAIN}" \
  --set "dummycontentsigner.config.credential_endpoint=https://cloud-wallet.${DOMAIN}/api/issuance/credential" \
  --set "dummycontentsigner.config.signerUrl=http://signer.${NAMESPACE}.svc.cluster.local:8080/v1/credential" \
  --set "dummycontentsigner.config.nats.url=nats://nats.nats.svc.cluster.local:4222"
