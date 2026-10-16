#!/bin/bash
# Downloads the AWS RDS global CA bundle on each deployment so the app can
# verify the RDS server certificate. Set the environment property:
#   RDS_CA_BUNDLE=/etc/pki/rds/global-bundle.pem
set -euo pipefail
mkdir -p /etc/pki/rds
curl -fsSL -o /etc/pki/rds/global-bundle.pem \
  https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem
chmod 644 /etc/pki/rds/global-bundle.pem
