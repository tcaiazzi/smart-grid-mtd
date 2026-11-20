# Kathará node image for DFIR-IRIS's application and worker in the cps-soc lab:
# the official image (the same one runs both, as in IRIS's own compose file),
# with what a lab node needs on top.
FROM ghcr.io/dfir-iris/iriswebapp_app:v2.4.29

RUN apt-get update && apt-get install -y --no-install-recommends iproute2 iptables && \
    rm -rf /var/lib/apt/lists/*

# Kathará runs every command of the node from here, and the platform reads a
# service's console log at the root: the official image works elsewhere.
WORKDIR /

LABEL org.smartgrid-mtd.role="cps-soc-iris-app" \
      org.smartgrid-mtd.description="DFIR-IRIS application / worker of the cps-soc lab"
