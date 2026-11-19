# The cps-soc lab's own certificate authority, and the certificates of the
# services that speak TLS to each other: the Wazuh indexer, its dashboard, the
# manager's alert shipper, and IRIS's web front. Built once, then copied into
# each service's image (COPY --from=kathara/wazuh-pki): certificates generated
# image by image would come from different authorities, and no service would
# trust another.
#
# The distinguished names are the ones the indexer's security plugin is told
# to trust (nodes/wazuh/indexer/opensearch.yml: nodes_dn, admin_dn). The
# certificates name services, not addresses: the lab's nodes dial the services
# by these names (cyberrange/scenarios/cps_soc/feature.py writes them into
# /etc/hosts), so a lab that moves a service needs no new image. IRIS's also
# names 127.0.0.1, where the team's browser reaches it. A lab
# certificate authority: its keys sit in the images and protect nothing beyond
# the lab.
FROM debian:12-slim

RUN apt-get update && apt-get install -y --no-install-recommends openssl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /pki
# Keys are PKCS#8 (genpkey's default): the indexer reads no other PEM key form.
RUN set -eu; \
    O="/OU=Wazuh/O=Wazuh/L=California/C=US"; \
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out root-ca.key; \
    openssl req -x509 -new -key root-ca.key -sha256 -days 3650 \
        -subj "/CN=cyber-range lab CA$O" -out root-ca.pem; \
    issue() { \
        name=$1 cn=$2 san=$3; \
        openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$name-key.pem"; \
        openssl req -new -key "$name-key.pem" -subj "/CN=$cn$O" -out "$name.csr"; \
        printf 'subjectAltName=%s\nextendedKeyUsage=serverAuth,clientAuth\n' "$san" > "$name.ext"; \
        openssl x509 -req -in "$name.csr" -CA root-ca.pem -CAkey root-ca.key -CAcreateserial \
            -sha256 -days 3650 -extfile "$name.ext" -out "$name.pem"; \
        rm "$name.csr" "$name.ext"; \
    }; \
    issue admin admin "DNS:admin"; \
    issue indexer wazuh.indexer "DNS:wazuh.indexer"; \
    issue dashboard wazuh.dashboard "DNS:wazuh.dashboard"; \
    issue manager wazuh.manager "DNS:wazuh.manager"; \
    issue iris iris.lab "DNS:iris.lab,IP:127.0.0.1"; \
    rm root-ca.key root-ca.srl; \
    chmod 444 /pki/*

LABEL org.smartgrid-mtd.role="cps-soc-pki" \
      org.smartgrid-mtd.description="Lab certificate authority for the cps-soc services"
