FROM ubuntu:16.04

## -----------------------------------------------------------------------------
## Installing dependencies
## -----------------------------------------------------------------------------
ENV DEBIAN_FRONTEND noninteractive
RUN set -xe \
	&& apt-get update \
	&& apt-get -y --no-install-recommends install \
		software-properties-common \
		apt-transport-https \
		ca-certificates \
		lsb-release \
		curl \
	&& add-apt-repository -y "deb https://packages.erlang-solutions.com/ubuntu $(lsb_release -sc) contrib" \
	&& curl -vs http://packages.erlang-solutions.com/ubuntu/erlang_solutions.asc 2>&1 | apt-key add -- \
	&& apt-get update \
	&& apt-get -y --no-install-recommends install \
		erlang-nox=1:19.0-1 \
		erlang-dialyzer \
		erlang-dev \
		mosquitto-clients \
		vim-nox \
		less \
		make \
		git

## -----------------------------------------------------------------------------
## Installing VerneMQ
## -----------------------------------------------------------------------------
RUN set -xe \
  && VERNEMQ_URI='https://bintray.com/artifact/download/erlio/vernemq/deb/xenial/vernemq_0.14.2-1_amd64.deb' \
  && VERNEMQ_SHA1='74f24b602534a8b2295634b7d233d364d3001b19' \
  && curl -fSL -o vernemq.deb "${VERNEMQ_URI}" \
    && echo "${VERNEMQ_SHA1} vernemq.deb" | sha1sum -c - \
    && set +e; dpkg -i vernemq.deb || apt-get -y -f --no-install-recommends install; set -e \
    && rm vernemq.deb

