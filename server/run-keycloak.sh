#!/usr/bin/env bash

##########
#
# Start Keycloak with the environment variables defined by the 3 .env files.
#
#########

set -euo pipefail

CURRENTDIR=$(dirname "$0")

export $(grep -v '^#' "${CURRENTDIR}"/../docker-compose/src/main/resources/keycloak.common.env | xargs)
export $(grep -v '^#' "${CURRENTDIR}"/../docker-compose/src/main/resources/keycloak.specific.env | xargs)
export $(grep -v '^#' "${CURRENTDIR}"/../docker-compose/src/main/resources/secrets.env | xargs)

# Define log levels using an associative array
declare -A LOG_LEVELS=(
  ["root"]="DEBUG"
  ["hibernate.hql.internal.ast"]="INFO"
  ["org.hibernate.orm.sql.ast"]="INFO"
  ["org.hibernate.query.sqm.sql"]="INFO"
  ["org.hibernate.orm.jdbc.batch"]="INFO"
  ["org.hibernate.SQL"]="INFO"
)

# Build the log-level string
LOG_LEVEL_STRING=""
for logger in "${!LOG_LEVELS[@]}"; do
  if [ "$logger" = "root" ]; then
    LOG_LEVEL_STRING="${LOG_LEVELS[$logger]}"
  else
    LOG_LEVEL_STRING="${LOG_LEVEL_STRING},${logger}:${LOG_LEVELS[$logger]}"
  fi
done

# set the working directory as in the docker image
cd "${CURRENTDIR}"/target/keycloak/
bash ./bin/kc.sh --debug start-dev --log-level="${LOG_LEVEL_STRING}"
