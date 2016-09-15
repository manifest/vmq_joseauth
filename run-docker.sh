#!/bin/sh

VMQ_JOSEAUTH_DIR='/opt/manifest/vmq_joseauth'

read -r DOCKER_RUN_COMMAND <<-EOF
	vernemq start \
	&& vmq-admin plugin disable --name vmq_passwd \
	&& vmq-admin plugin disable --name vmq_acl
EOF

docker build -t manifest/vmq_joseauth .
docker run -ti --rm \
	-v $(pwd):${VMQ_JOSEAUTH_DIR} \
	-p 1883:1883 \
	-p 8888:8888 \
	manifest/vmq_joseauth \
	/bin/bash -c "set -x && ${DOCKER_RUN_COMMAND} && set +x && cd ${VMQ_JOSEAUTH_DIR} && /bin/bash"
