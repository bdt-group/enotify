%%%-------------------------------------------------------------------
%%% @author Evgeny Khramtsov <ekhramtsov@bdt.group>
%%% @copyright (C) 2021, Big Data Technology. All Rights Reserved.
%%%
%%% Licensed under the Apache License, Version 2.0 (the "License");
%%% you may not use this file except in compliance with the License.
%%% You may obtain a copy of the License at
%%%
%%%     http://www.apache.org/licenses/LICENSE-2.0
%%%
%%% Unless required by applicable law or agreed to in writing, software
%%% distributed under the License is distributed on an "AS IS" BASIS,
%%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%%% See the License for the specific language governing permissions and
%%% limitations under the License.
%%% @doc
%%% @end
%%% Created :  7 Feb 2021 by Evgeny Khramtsov <ekhramtsov@bdt.group>
%%%-------------------------------------------------------------------
-module(enotify).

-on_load(load_nif/0).

%% API
-export([watch_dir/1]).
-export([rm_watch/1]).
%% Shut up xref
-export([load_nif/0]).
%% Exported types
-export_type([descriptor/0]).
-export_type([event/0]).
-export_type([event_type/0]).
-export_type([error_reason/0]).

-opaque descriptor() :: reference().
-type error_reason() :: string().
-type event() :: {enotify_event, descriptor(), event_type()} |
                 {enotify_critical, descriptor(), string()}.
-type event_type() :: {close_write, file, file:filename()} |
                      {moved_to, file, file:filename()}.

%%%===================================================================
%%% API
%%%===================================================================
-spec watch_dir(file:name_all()) -> {ok, descriptor()} | {error, error_reason()}.
watch_dir(Dir) when is_atom(Dir) ->
    watch_dir(atom_to_binary(Dir, unicode));
watch_dir(Dir) ->
    try unicode:characters_to_binary(Dir) of
        BDir when is_binary(BDir) ->
            watch_dir_nif(BDir);
        _ ->
            erlang:error(badarg, [Dir])
    catch _:_ ->
            erlang:error(badarg, [Dir])
    end.

-spec rm_watch(descriptor()) -> ok.
rm_watch(Ref) when is_reference(Ref) ->
    rm_watch_nif(Ref);
rm_watch(Arg) ->
    erlang:error(badarg, [Arg]).

watch_dir_nif(_) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

rm_watch_nif(_) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%%%===================================================================
%%% Internal functions
%%%===================================================================
-spec load_nif() -> ok | {error, term()}.
load_nif() ->
    EbinDir = filename:dirname(code:which(?MODULE)),
    AppDir = filename:dirname(EbinDir),
    PrivDir = filename:join([AppDir, "priv"]),
    SOPath = filename:join(PrivDir, ?MODULE),
    erlang:load_nif(SOPath, 0).
