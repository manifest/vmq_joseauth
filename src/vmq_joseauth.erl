%% ----------------------------------------------------------------------------
%% The MIT License
%%
%% Copyright (c) 2016 Andrei Nesterov <ae.nesterov@gmail.com>
%%
%% Permission is hereby granted, free of charge, to any person obtaining a copy
%% of this software and associated documentation files (the "Software"), to
%% deal in the Software without restriction, including without limitation the
%% rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
%% sell copies of the Software, and to permit persons to whom the Software is
%% furnished to do so, subject to the following conditions:
%%
%% The above copyright notice and this permission notice shall be included in
%% all copies or substantial portions of the Software.
%%
%% THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
%% IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
%% FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
%% AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
%% LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
%% FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
%% IN THE SOFTWARE.
%% ----------------------------------------------------------------------------

-module(vmq_joseauth).
-behaviour(auth_on_register_hook).
-include_lib("vmq_commons/include/vmq_types.hrl").

%% API
-export([
	load_key/1,
	load_key/2,
	load_keys/0,
	remove_keys/0
]).

%% Hooks
-export([
	auth_on_register/5
]).

%% Plugin Callbacks
-export([
	start/0,
	stop/0
]).

%% Configuration
-export([
	keys_directory/0,
	verify_options/0,
	success_result/0
]).

%% Definitions
-define(TAB, ?MODULE).
-define(APP, ?MODULE).

%% Types
-record(k_identity, {
	iss        :: binary(),
	kid = <<>> :: binary()
}).

-type k_identity() :: #k_identity{}.

-record(k_struct, {
	identity      :: k_identity(),
	alg           :: binary(),
	key           :: binary(),
	options = #{} :: map()
}).

-type k_struct() :: #k_struct{}.

%% =============================================================================
%% API
%% =============================================================================

-spec load_key(binary()) -> ok.
load_key(FileName) ->
	load_key(FileName, verify_options()).

-spec load_key(binary(), jose_claim:verify_options()) -> ok.
load_key(FileName, Opts) ->
	try
		ets:insert(?TAB, k_struct(FileName, Opts)),
		error_logger:info_report(
			[	{?MODULE, ?FUNCTION_NAME, ?FUNCTION_ARITY},
				{keyfile, FileName} ])
	catch T:R ->
		error_logger:error_report(
			[	{?MODULE, ?FUNCTION_NAME, ?FUNCTION_ARITY, erlang:get_stacktrace(), T, R},
				{keyfile, FileName} ])
	end.

-spec load_keys() -> ok.
load_keys() ->
	catch ?TAB = ets:new(?TAB, [named_table, {keypos, #k_struct.identity}, {read_concurrency, true}]),

	Dir = keys_directory(),
	{ok, Files} = file:list_dir_all(Dir),
	_ = [load_key(filename:join(Dir, F), verify_options()) || F <- Files],
	ok.

-spec remove_keys() -> ok.
remove_keys() ->
	ets:delete(?TAB),
	ok.

%% =============================================================================
%% Hooks
%% =============================================================================

auth_on_register(_Peer, _SubscriberId, _UserName, undefined, _CleanSession) ->
	Reason = missing_access_token,
	error_logger:info_report([{?MODULE, ?FUNCTION_NAME, ?FUNCTION_ARITY, erlang:get_stacktrace(), error, Reason}]),
	{error, Reason};
auth_on_register(_Peer, _SubscriberId, _UserName, Password, _CleanSession) ->
	try
		_ = jose_jws_compact:decode_fn(fun select_key/2, Password),
		success_result()
	catch _:R ->
		Reason = {bad_access_token, R},
		error_logger:info_report(
			[	{?MODULE, ?FUNCTION_NAME, ?FUNCTION_ARITY, erlang:get_stacktrace(), error, Reason},
				{access_token, Password} ]),
		{error, Reason}
	end.

%% =============================================================================
%% Plugin Callbacks
%% =============================================================================

-spec start() -> ok.
start() ->
	{ok, _} = application:ensure_all_started(?APP),
	load_keys().

-spec stop() -> ok.
stop() ->
	remove_keys(),
	application:stop(?APP).

%% =============================================================================
%% Configuration
%% =============================================================================

-spec keys_directory() -> binary().
keys_directory() ->
	priv_path(list_to_binary(application:get_env(?APP, ?FUNCTION_NAME, "keys"))).

-spec verify_options() -> jose_claim:verify_options().
verify_options() ->
	Default = #{verify => [exp, nbf, iat]},
	application:get_env(?APP, verify_options, Default).

-spec success_result() -> ok | next.
success_result() ->
	application:get_env(?APP, success_result, ok).

%% =============================================================================
%% Internal functions
%% =============================================================================

-spec select_key(list(), jose_jws_compact:parse_options()) -> jose_jws_compact:select_key_result().
select_key([ #{<<"kid">> := Kid}, #{<<"iss">> := Iss} | _ ], _Opts) ->
	handle_k_struct(ets:lookup(?TAB, #k_identity{iss = Iss, kid = Kid}));
select_key([ _Header, #{<<"iss">> := Iss} | _ ], _Opts) ->
	handle_k_struct(ets:lookup(?TAB, #k_identity{iss = Iss}));
select_key(_Data, _Opts) ->
	{error, missing_iss}.

-spec handle_k_struct([k_struct()]) -> jose_jws_compact:select_key_result().
handle_k_struct([#k_struct{alg = Alg, key = Key, options = Opts}]) ->
	{ok, {Alg, Key, Opts}};
handle_k_struct([]) ->
	{error, missing_k_struct}.

-spec k_struct(binary(), jose_claim:verify_options()) -> k_struct().
k_struct(FileName, Opts) ->
	k_struct(filename:basename(FileName), FileName, Opts).

-spec k_struct(binary(), binary(), jose_claim:verify_options()) -> k_struct().
k_struct(<<"der:", R/binary>>, FileName, Opts) ->
	{ok, Key} = file:read_file(FileName),
	k_struct_iss(R, <<>>, undefined, Key, Opts);
k_struct(<<"pem:", R/binary>>, FileName, Opts) ->
	{ok, Data} = file:read_file(FileName),
	{Alg, Key} = jose_pem:parse_key(Data),
	k_struct_iss(R, <<>>, Alg, Key, Opts);
k_struct(_BaseName, FileName, _Opts) ->
	error({bad_keyfile, FileName}).

-spec k_struct_iss(binary(), binary(), undefined | binary(), binary(), jose_claim:verify_options()) -> k_struct().
k_struct_iss(<<>>, Acc, Alg, Key, Opts) when is_binary(Alg) ->
	#k_struct{identity = #k_identity{iss = Acc}, alg = Alg, key = Key, options = Opts};
k_struct_iss(<<$:, R/bits>>, Acc, Alg, Key, Opts) ->
	k_struct_kid(R, <<>>, Alg, Key, Opts, Acc);
k_struct_iss(<<C, R/bits>>, Acc, Alg, Key, Opts) ->
	k_struct_iss(R, <<Acc/binary, C>>, Alg, Key, Opts).

-spec k_struct_kid(binary(), binary(), undefined | binary(), binary(), jose_claim:verify_options(), binary()) -> k_struct().
k_struct_kid(<<>>, Acc, Alg, Key, Opts, Iss) when is_binary(Alg) ->
	#k_struct{identity = #k_identity{iss = Iss, kid = Acc}, alg = Alg, key = Key, options = Opts};
k_struct_kid(<<C, _/bits>>, Acc, Alg, Key, Opts, Iss) when is_binary(Alg) andalso ((C =:= $:) orelse (C =:= $.)) ->
	#k_struct{identity = #k_identity{iss = Iss, kid = Acc}, alg = Alg, key = Key, options = Opts};
k_struct_kid(<<$:, R/bits>>, Acc, _Alg, Key, Opts, Iss) ->
	k_struct_alg(R, <<>>, Key, Opts, Iss, Acc);
k_struct_kid(<<C, R/bits>>, Acc, Alg, Key, Opts, Iss) ->
	k_struct_kid(R, <<Acc/binary, C>>, Alg, Key, Opts, Iss).

-spec k_struct_alg(binary(), binary(), binary(), jose_claim:verify_options(), binary(), binary()) -> k_struct().
k_struct_alg(<<>>, Acc, Key, Opts, Iss, Kid) ->
	#k_struct{identity = #k_identity{iss = Iss, kid = Kid}, alg = Acc, key = Key, options = Opts};
k_struct_alg(<<C, _/bits>>, Acc, Key, Opts, Iss, Kid) when (C =:= $:) orelse (C =:= $.) ->
	#k_struct{identity = #k_identity{iss = Iss, kid = Kid}, alg = Acc, key = Key, options = Opts};
k_struct_alg(<<C, R/bits>>, Acc, Key, Opts, Iss, Kid) ->
	k_struct_alg(R, <<Acc/binary, C>>, Key, Opts, Iss, Kid).

-spec priv_path(binary()) -> binary().
priv_path(Path) ->
	Priv =
		case code:priv_dir(?APP) of
			{error, _} -> "priv";
			Dir -> Dir
		end,
	<<(list_to_binary(Priv))/binary, $/, Path/binary>>.
