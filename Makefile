PROJECT = vmq_joseauth
PROJECT_DESCRIPTION = VerneMQ JOSE Authentication Plugin
PROJECT_VERSION = 0.1.0

DEPS = \
	vmq_commons \
	jose

dep_vmq_commons = git git://github.com/erlio/vmq_commons.git 0.9.4
dep_jose = git git://github.com/manifest/jose-erlang.git master

SHELL_DEPS = tddreloader
SHELL_OPTS = \
	-eval 'application:ensure_all_started($(PROJECT), permanent)' \
	-s tddreloader start \
	-config rel/sys

include erlang.mk

PLUGIN_HOOKS=[{vmq_joseauth, auth_on_register, 5, []}]
app::
	perl -pi -e "s/(]}\.)/\t,{env, [{vmq_plugin_hooks, $(PLUGIN_HOOKS)}]}\n\1/" ebin/vmq_joseauth.app
