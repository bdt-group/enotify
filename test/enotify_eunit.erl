%%%-------------------------------------------------------------------
%%% @author Evgeny Khramtsov <ekhramtsov@bdt.group>
%%% @copyright (C) 2021, Big Data Technology
%%% @doc
%%%
%%% @end
%%% Created :  7 Feb 2021 by Evgeny Khramtsov <ekhramtsov@bdt.group>
%%%-------------------------------------------------------------------
-module(enotify_eunit).
-compile(export_all).
-compile(nowarn_export_all).

-include_lib("eunit/include/eunit.hrl").

%%%===================================================================
%%% Tests
%%%===================================================================
watch_dir_close_write_test() ->
    Dir = tmp_dir(),
    File = "test1",
    {ok, Ref} = enotify:watch_dir(Dir),
    touch(Dir, File),
    receive
        {enotify_event, Ref, {close_write, file, File}} ->
            enotify:rm_watch(Ref);
        Unexpected ->
            erlang:error({unexpected_message, Unexpected})
    end.

watch_dir_moved_to_test() ->
    Dir = tmp_dir(),
    File1 = "test1",
    File2 = "test2",
    touch(Dir, File1),
    {ok, Ref} = enotify:watch_dir(Dir),
    ok = file:rename(filename:join(Dir, File1), filename:join(Dir, File2)),
    receive
        {enotify_event, Ref, {moved_to, file, File2}} ->
            enotify:rm_watch(Ref);
        Unexpected ->
            erlang:error({unexpected_message, Unexpected})
    end.

watch_dir_enoent_test() ->
    ?assertMatch({error, _}, enotify:watch_dir('non-existent-watch-dir')).

bad_dirname_test() ->
    ?assertError(badarg, enotify:watch_dir({})),
    ?assertError(badarg, enotify:watch_dir([16#fffffffff])).

rm_watch_non_existent_test() ->
    ?assertEqual(ok, enotify:rm_watch(make_ref())).

rm_watch_badarg_test() ->
    ?assertError(badarg, enotify:rm_watch([])).

%%%===================================================================
%%% Internal functions
%%%===================================================================
tmp_dir() ->
    Dir = filename:basedir(user_cache, "enotify", #{author => eunit}),
    ?assertEqual(ok, filelib:ensure_dir(filename:join(Dir, "."))),
    Dir.

touch(Dir, File) ->
    file:write_file(filename:join(Dir, File), <<>>).
