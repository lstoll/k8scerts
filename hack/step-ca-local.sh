#!/bin/bash
set -euo pipefail

echo "Starting Step-CA locally..."
CONFIG_DIR=$(pwd)/k8s/step-ca

docker run --rm -it -p 9000:9000 -v "${CONFIG_DIR}:/home/step/config" -v "${CONFIG_DIR}:/home/step/certs" smallstep/step-ca:latest /home/step/config/ca.json
