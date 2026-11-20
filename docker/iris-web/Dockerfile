# Kathará node image for DFIR-IRIS's web front (nginx) in the cps-soc lab: the
# official image with what a lab node needs on top, and the lab's certificate.
#
# Root: Kathará runs a node's startup commands as the image's user, and the
# official one (www-data) cannot address an interface.
FROM ghcr.io/dfir-iris/iriswebapp_nginx:v2.4.29

USER root
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 iptables && \
    rm -rf /var/lib/apt/lists/*

COPY --from=kathara/wazuh-pki /pki/iris.pem /www/certs/iris_lab_cert.pem
COPY --from=kathara/wazuh-pki /pki/iris-key.pem /www/certs/iris_lab_key.pem

# Kathará runs every command of the node from here, and the platform reads a
# service's console log at the root: the official image works elsewhere.
WORKDIR /

LABEL org.smartgrid-mtd.role="cps-soc-iris-web" \
      org.smartgrid-mtd.description="DFIR-IRIS web front of the cps-soc lab"
