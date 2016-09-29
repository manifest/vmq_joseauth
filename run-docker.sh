#!/bin/sh

PROJECT_DIR='/opt/sandbox/vmq_joseauth'

read -r DOCKER_RUN_COMMAND <<-EOF
	vernemq start \
	&& vmq-admin plugin disable --name vmq_passwd \
	&& vmq-admin plugin disable --name vmq_acl
EOF

docker build -t sandbox/vmq_joseauth .
docker run -ti --rm \
	-v $(pwd):${PROJECT_DIR} \
	-p 1883:1883 \
	-p 8888:8888 \
	sandbox/vmq_joseauth \
	/bin/bash -c "set -x && ${DOCKER_RUN_COMMAND} && set +x && cd ${PROJECT_DIR} && /bin/bash"
