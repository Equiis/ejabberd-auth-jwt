%%%-------------------------------------------------------------------
%%% @author Vincent Labreche
%%% @copyright (C) 2016, Equiis Technologies
%%% @doc
%%% This module will verify an incoming JWT token and confirm the username claim is present in the request.
%%% - Store your key in the "secret" key/value pair ejabberd_auth_jwt.app setting.
%%% - HS256/RS256 support
%%% - The user_id is the only required claim and must match the username passed into eJabberd.
%%% - Optionally, pass a "Host" claim and it will check the eJabberd server name for equality.
%%% @end
%%%-------------------------------------------------------------------

-module(ejabberd_auth_jwt).
-author('Vincent Labreche <vlabreche@equiis.com').

-behaviour(ejabberd_auth).
-behaviour(ejabberd_config).

%% API
-export([
  start/1,
  start/2,
  store_type/0,
  plain_password_required/0,
  check_password/3,
  is_user_exists/2,
  stop/1]).

-include_lib("ejabberd.hrl").
-include_lib("logger.hrl").

-define(PROCNAME, ejabberd_auth_jwt).

%% Implementation

start(_Host) ->
  ?INFO_MSG("JWT auth started", []),
  ok.

start(_Host, _Opts) ->
  ?INFO_MSG("JWT auth started", []),
  ok.

stop(_Host) ->
  ?INFO_MSG("JWT auth stopped", []),
  ok.

% Needed so that the check_password/3 is called.
plain_password_required() -> true.

% Needed so that the check_password/3 is called.
store_type() -> external.

is_user_exists(User, _Server) ->
  error_logger:info_msg(User),
  true.

-spec check_password(ejabberd:luser(), ejabberd:lserver(), binary()) -> boolean().
check_password(LUser, LServer, Token) ->
  error_logger:info_msg(io_lib:format("Unwrapping token ~s for User ~s at ~s", [Token, LUser, LServer])),

  % shared key data
  application:load(ejabberd_auth_jwt),
  {_, Key} = application:get_env(ejabberd_auth_jwt, secret),

  % Get the asserted user id
  ParsedClaims = ejwt:parse_jwt(Token, Key),

  case ParsedClaims of
    invalid ->
      error_logger:info_msg("Invalid Token for ~s", [LUser]),
      false;
    expired ->
      error_logger:info_msg("Token has expired for ~s", [LUser]),
      false;
    {AssertedClaims} ->
      Uid = proplists:get_value(<<"user_id">>, AssertedClaims),
      Host = proplists:get_value(<<"host">>, AssertedClaims),

      % if the claim passes a host then also check this
      case Host of
        undefined ->
          % Check that the authenticated
          if LUser == Uid ->
            true;
            true ->
              error_logger:info_msg("Invalid Claim for ~s for as ~s", [LUser, Uid]),
              false
          end;
        _ ->
          % Check that the authenticated
          if LUser == Uid andalso LServer == Host ->
            true;
            true ->
              error_logger:info_msg("Invalid Claim for ~s as ~s on ~s", [LUser, Uid, LServer]),
              false
          end
      end
  end.
