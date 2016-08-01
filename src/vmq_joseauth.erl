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

%% API
-export([
	load_key/1,
	load_key/2,
	load_keys/0,
	remove_keys/0,
	match_pattern/3,
	read_config/1
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
	client_id_pattern/0,
	username_pattern/0,
	keys_directory/0,
	verify_options/0,
	auth_on_register_success_result/0,
	config_file/0
]).

%% Definitions
-define(TAB, ?MODULE).
-define(APP, ?MODULE).

-type pattern() :: [binary() | {claim, binary()} | rest].
-type pattern_input() :: {eq | {non_neg_integer(), non_neg_integer()}, binary()}.

%% Types
-record(k_identity, {
	iss :: binary(),
	kid = <<>> :: binary()
}).

-type k_identity() :: #k_identity{}.

-record(k_struct, {
	identity :: k_identity(),
	alg :: binary(),
	key :: binary(),
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

-spec match_pattern(pattern(), map(), binary()) -> ok.
match_pattern(Pattern, Claims, Input) ->
	match_pattern_input(pattern_input(Pattern, Claims), Input).

%% =============================================================================
%% Hooks
%% =============================================================================

auth_on_register(_Peer, _SubscriberId, _UserName, undefined, _CleanSession) ->
	Reason = missing_access_token,
	error_logger:info_report([{?MODULE, ?FUNCTION_NAME, ?FUNCTION_ARITY, erlang:get_stacktrace(), error, Reason}]),
	{error, Reason};
auth_on_register(_Peer, {_MountPoint, ClientId}, UserName, Password, _CleanSession) ->
	try
		Claims = jose_jws_compact:decode_fn(fun select_key/2, Password),
		match_pattern(username_pattern(), Claims, UserName),
		match_pattern(client_id_pattern(), Claims, ClientId),
		auth_on_register_success_result()
	catch _:R ->
		Reason = {bad_access_token, R},
		error_logger:info_report(
			[	{?MODULE, ?FUNCTION_NAME, ?FUNCTION_ARITY, erlang:get_stacktrace(), error, Reason},
				{access_token, Password}]),

		{error, Reason}
	end.

%% =============================================================================
%% Plugin Callbacks
%% =============================================================================

-spec start() -> ok.
start() ->
	{ok, _} = application:ensure_all_started(?APP),
	read_config(config_file()),
	load_keys().

-spec stop() -> ok.
stop() ->
	remove_keys(),
	application:stop(?APP).

%% =============================================================================
%% Configuration
%% =============================================================================

-spec client_id_pattern() -> pattern().
client_id_pattern() ->
	application:get_env(?APP, ?FUNCTION_NAME, [rest]).

-spec username_pattern() -> pattern().
username_pattern() ->
	application:get_env(?APP, ?FUNCTION_NAME, [rest]).

-spec keys_directory() -> binary().
keys_directory() ->
	priv_path(list_to_binary(application:get_env(?APP, ?FUNCTION_NAME, "keys"))).

-spec verify_options() -> jose_claim:verify_options().
verify_options() ->
	Default = #{verify => [exp, nbf, iat]},
	application:get_env(?APP, ?FUNCTION_NAME, Default).

-spec auth_on_register_success_result() -> ok | next.
auth_on_register_success_result() ->
	application:get_env(?APP, ?FUNCTION_NAME, ok).

-spec config_file() -> binary().
config_file() ->
	list_to_binary(application:get_env(?APP, ?FUNCTION_NAME, "./etc/joseauth.conf")).

-spec read_config(binary()) -> ok.
read_config(Path) ->
	_ =
		case file:consult(Path) of
			{ok, L} -> [application:set_env(?APP, Key, Val) || {Key, Val} <- L];
			_       -> ignore
		end,
	ok.

%% =============================================================================
%% Internal functions
%% =============================================================================

-spec match_pattern_input(pattern_input(), binary()) -> ok.
match_pattern_input({eq, Val}, Val)                    -> ok;
match_pattern_input({{Pos, Len}, Val} = PInput, Input) ->
	case Input of
		<<_:Pos/binary, Val:Len/binary, _/bits>> -> ok;
		_                                        -> error({nomatch_pattern, Input, PInput})
	end.

-spec pattern_input(pattern(), map()) -> pattern_input().
pattern_input(Pattern, Claims) ->
	pattern_input(Pattern, Claims, <<>>).

-spec pattern_input(pattern(), map(), binary()) -> pattern_input().
pattern_input([], _Claims, Acc) ->
	{eq, Acc};
pattern_input([rest|_], _Claims, Acc) ->
	{{0, byte_size(Acc)}, Acc};
pattern_input([{claim, Name}|T], Claims, Acc) ->
	case maps:find(Name, Claims) of
		{ok, Val} -> pattern_input(T, Claims, <<Acc/binary, Val/binary>>);
		_         -> error({missing_claim, Name})
	end;
pattern_input([Val|T], Claims, Acc) ->
	pattern_input(T, Claims, <<Acc/binary, Val/binary>>).

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
			Dir        -> Dir
		end,
	<<(list_to_binary(Priv))/binary, $/, Path/binary>>.

%% =============================================================================
%% Tests
%% =============================================================================

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

match_pattern_input_test_() ->
	Test =
		[	%% equal
			{[], #{}, {eq, <<>>}},
			{[<<>>], #{}, {eq, <<>>}},
			{[<<"user">>], #{}, {eq, <<"user">>}},
			{[<<"user/">>, {claim, <<"sub">>}], #{<<"sub">> => <<"joe">>}, {eq, <<"user/joe">>}},
			{[<<"user/">>, {claim, <<"sub">>}, <<"/">>], #{<<"sub">> => <<"joe">>}, {eq, <<"user/joe/">>}},
			{[<<>>, {claim, <<"sub">>}], #{<<"sub">> => <<"joe">>}, {eq, <<"joe">>}},
			%% w/ rest
			{[rest], #{}, {{0, 0}, <<>>}},
			{[<<>>, rest], #{}, {{0, 0}, <<>>}},
			{[<<"user">>, rest], #{}, {{0, 4}, <<"user">>}},
			{[<<"user/">>, {claim, <<"sub">>}, rest], #{<<"sub">> => <<"joe">>}, {{0, 8}, <<"user/joe">>}},
			{[<<"user/">>, {claim, <<"sub">>}, <<"/">>, rest], #{<<"sub">> => <<"joe">>}, {{0, 9}, <<"user/joe/">>}},
			{[rest, <<"any">>], #{}, {{0, 0}, <<>>}} ],

	[{lists:flatten(io_lib:format("~p", [Pattern])), ?_assertEqual(Output, pattern_input(Pattern, Claims))}
		|| {Pattern, Claims, Output} <- Test].

match_pattern_test_() ->
	Test =
		[	%% equal
			{[], #{}, <<>>},
			{[<<>>], #{}, <<>>},
			{[<<"user">>], #{}, <<"user">>},
			{[<<"user/">>, {claim, <<"sub">>}], #{<<"sub">> => <<"joe">>}, <<"user/joe">>},
			{[<<"user/">>, {claim, <<"sub">>}, <<"/">>], #{<<"sub">> => <<"joe">>}, <<"user/joe/">>},
			{[<<>>, {claim, <<"sub">>}], #{<<"sub">> => <<"joe">>}, <<"joe">>},
			%% w/ rest
			{[rest], #{}, <<>>},
			{[<<>>, rest], #{}, <<>>},
			{[<<"user">>, rest], #{}, <<"user">>},
			{[<<"user/">>, {claim, <<"sub">>}, rest], #{<<"sub">> => <<"joe">>}, <<"user/joe">>},
			{[<<"user/">>, {claim, <<"sub">>}, <<"/">>, rest], #{<<"sub">> => <<"joe">>}, <<"user/joe/">>},
			{[<<>>, {claim, <<"sub">>}, rest], #{<<"sub">> => <<"joe">>}, <<"joe">>},
			{[rest, <<"any">>], #{}, <<>>}
		],

	[{lists:flatten(io_lib:format("~p", [Pattern])), ?_assertEqual(ok, match_pattern(Pattern, Claims, Input))}
		|| {Pattern, Claims, Input} <- Test].

-endif.
