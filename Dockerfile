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
		erlang-dev=1:19.0-1 \
		mosquitto-clients \
		vim-nox \
		less \
		make \
		git

## -----------------------------------------------------------------------------
## Installing VerneMQ
## -----------------------------------------------------------------------------
RUN set -xe \
  && VERNEMQ_URI='https://bintray.com/artifact/download/erlio/vernemq/deb/xenial/vernemq_0.13.1-1_amd64.deb' \
  && VERNEMQ_SHA1='7505dca98fb0f9551e1c0ff7d126e20c1296022f' \
  && curl -fSL -o vernemq.deb "${VERNEMQ_URI}" \
    && echo "${VERNEMQ_SHA1} vernemq.deb" | sha1sum -c - \
    && set +e; dpkg -i vernemq.deb || apt-get -y -f --no-install-recommends install; set -e \
    && rm vernemq.deb

