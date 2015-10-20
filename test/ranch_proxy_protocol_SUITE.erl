-module(ranch_proxy_protocol_SUITE).

-include_lib("common_test/include/ct.hrl").
-compile(export_all).

all() ->
    [ new_connection, new_connection_encoder, new_connection_v2,
      proxy_connect, reuse_socket, fail_not_proxy_clean,
      fail_garbage_clean, fail_timeout_clean ].

init_per_suite(Config) ->
    application:ensure_all_started(ranch),
    application:load(ranch_proxy_protocol),
    Config.

init_per_testcase(new_connection, Config) ->
    Port = 9401,
    {ok, Pid} = ranch:start_listener(ranch_proxy_protocol_acceptor,
                                     1,
                                     ranch_proxy,
                                     [{port, Port}],
                                     ranch_proxy_protocol_test_protocol, [{tester, self()}]),
    [{port, Port},
     {listeners, Pid} | Config];
init_per_testcase(new_connection_encoder, Config) ->
    Port = 9401,
    {ok, Pid} = ranch:start_listener(ranch_proxy_protocol_acceptor,
                                     1,
                                     ranch_proxy,
                                     [{port, Port}],
                                     ranch_proxy_protocol_test_protocol, [{tester, self()}]),
    [{port, Port},
     {listeners, Pid} | Config];
init_per_testcase(new_connection_v2, Config) ->
    Port = 9401,
    {ok, Pid} = ranch:start_listener(ranch_proxy_protocol_acceptor,
                                     1,
                                     ranch_proxy,
                                     [{port, Port}],
                                     ranch_proxy_protocol_test_protocol, [{tester, self()}]),
    [{port, Port},
     {listeners, Pid} | Config];
init_per_testcase(proxy_connect, Config) ->
    Port = 9401,
    {ok, Pid} = ranch:start_listener(ranch_proxy_protocol_acceptor,
                                     1,
                                     ranch_proxy,
                                     [{port, Port}],
                                     ranch_proxy_protocol_test_protocol, [{tester, self()}]),
    [{port, Port},
     {listeners, Pid} | Config];
init_per_testcase(reuse_socket, Config) ->
    Port = 9401,
    {ok, Pid} = ranch:start_listener(ranch_proxy_protocol_acceptor,
                                     1,
                                     ranch_proxy,
                                     [{port, Port}],
                                     ranch_proxy_protocol_test_protocol, [{tester, self()}]),
    [{port, Port},
     {listeners, Pid} | Config];
init_per_testcase(fail_not_proxy_clean, Config) ->
    Port = 9401,
    {ok, Listen} = ranch_proxy:listen([{port, Port}]),
    Acceptor = start_acceptor(Listen),
    [{port, Port},
     {acceptor, Acceptor},
     {listen, Listen} | Config];
init_per_testcase(fail_garbage_clean, Config) ->
    Port = 9401,
    {ok, Listen} = ranch_proxy:listen([{port, Port}]),
    Acceptor = start_acceptor(Listen),
    [{port, Port},
     {acceptor, Acceptor},
     {listen, Listen} | Config];
init_per_testcase(fail_timeout_clean, Config) ->
    Port = 9401,
    %% override the timeout to cause a failure quickly
    Timeout = application:get_env(ranch_proxy_protocol, proxy_protocol_timeout),
    application:set_env(ranch_proxy_protocol, proxy_protocol_timeout, 250),
    {ok, Listen} = ranch_proxy:listen([{port, Port}]),
    [{port, Port},
     {listen, Listen},
     {timeout, Timeout} | Config].

end_per_testcase(fail_timeout_clean, Config) ->
    %% reset the timeout value
    case ?config(timeout, Config) of
        undefined ->
            application:unset_env(ranch_proxy_protocol, proxy_protocol_timeout);
        {ok, Val} ->
            application:set_env(ranch_proxy_protocol, proxy_protocol_timeout,
                                Val)
    end,
    Config;
end_per_testcase(_, Config) ->
    ranch:stop_listener(ranch_proxy_protocol_acceptor),
    Config.

%% Tests
new_connection(Config) ->
    Port = ?config(port, Config),
    {ok, Socket} = gen_tcp:connect({127,0,0,1}, Port,
                                   [binary, {active, false}, {packet, raw}]),
    ok = gen_tcp:send(Socket, "PROXY TCP4 192.168.1.1 192.168.1.2 80 81\r\n"),
    receive
        X ->
            {{{192,168,1,1}, 80}, {{192,168,1,2}, 81}} = X
    end,
    Config.

new_connection_encoder(Config) ->
    Port = ?config(port, Config),
    {ok, Socket} = gen_tcp:connect({127,0,0,1}, Port,
                                   [binary, {active, false}, {packet, raw}]),
    Bin = ranch_proxy_encoder:v1_encode(proxy, inet, {{192,168,1,1},80}, {{192,168,1,2},81}),
    ok = gen_tcp:send(Socket, Bin),
    receive
        X ->
            {{{192,168,1,1}, 80}, {{192,168,1,2}, 81}} = X
    end,
    Config.

new_connection_v2(Config) ->
    Port = ?config(port, Config),
    {ok, Socket} = gen_tcp:connect({127,0,0,1}, Port,
                                   [binary, {active, false}, {packet, raw}]),
    Bin = ranch_proxy_encoder:v2_encode(proxy, inet, {{127,50,210,1},64032}, {{210,21,16,142},437},
                                        [{sni_host, "example.org"}]),
    ok = gen_tcp:send(Socket, Bin),

    receive
        X ->
            {{{127,50,210,1},64032},{{210,21,16,142},437}} = X
    end,
    Config.

proxy_connect(Config) ->
    Port = ?config(port, Config),
    {ok, _Socket} = ranch_proxy:connect({127,0,0,1}, Port, [],
                                                  [{inet_version, ipv4},
                                                   {source_address, {192,168,0,3}},
                                                   {dest_address, {192,168,0,4}},
                                                   {source_port, 82},
                                                   {dest_port, 83}]),
    receive
        X ->
            {{{192,168,0,3}, 82}, {{192,168,0,4}, 83}} = X
    end,
    Config.

reuse_socket(Config) ->
    Port = ?config(port, Config),
    {ok, Socket} = ranch_proxy:connect({127,0,0,1}, Port, [],
                                                 [{inet_version, ipv4},
                                                  {source_address, {192,168,0,3}},
                                                  {dest_address, {192,168,0,4}},
                                                  {source_port, 82},
                                                  {dest_port, 83}]),
    receive
        X ->
            {{{192,168,0,3}, 82}, {{192,168,0,4}, 83}} = X
    end,
    ranch_proxy:close(Socket),
    {ok, Socket1} = ranch_proxy:connect({127,0,0,1}, Port, [],
                                                  [{source_address, {192,168,0,5}},
                                                   {dest_address, {192,168,0,6}},
                                                   {source_port, 84},
                                                   {dest_port, 85}]),
    receive
        X1 ->
            {{{192,168,0,5}, 84}, {{192,168,0,6}, 85}} = X1
    end,
    ranch_proxy:close(Socket1),
    Config.

fail_not_proxy_clean(Config) ->
    Port = ?config(port, Config),
    Acceptor = ?config(acceptor, Config),
    {ok, Conn} = gen_tcp:connect({127,0,0,1}, Port, [{active,false}]),
    gen_tcp:send(Conn, <<"PROXY GARBAGE\r\n">>),
    receive
        {Acceptor, {error, not_proxy_protocol}} ->
            [] = ports(Acceptor)
    after 5000 ->
        error(timeout)
    end.

fail_garbage_clean(Config) ->
    Port = ?config(port, Config),
    Acceptor = ?config(acceptor, Config),
    {ok, Conn} = gen_tcp:connect({127,0,0,1}, Port, [{active,false}]),
    gen_tcp:send(Conn, <<"garbage data\r\n">>),
    receive
        {Acceptor, {error, {tcp, _, _}}} ->
            [] = ports(Acceptor)
    after 5000 ->
        error(timeout)
    end.

fail_timeout_clean(Config) ->
    Port = ?config(port, Config),
    Listen = ?config(listen, Config),
    Acceptor = start_acceptor(Listen),
    {ok, Conn} = gen_tcp:connect({127,0,0,1}, Port, [{active,false}]),
    gen_tcp:send(Conn, <<"garbage data">>), % no CLRF may wait forever
    receive
        {Acceptor, {error, {timeout, proxy_handshake}}} ->
            [] = ports(Acceptor)
    after 5000 ->
        error(timeout)
    end.

%%% Helpers %%%
start_acceptor(Listen) ->
    Parent = self(),
    spawn_link(fun() ->
        Parent ! {self(), ranch_proxy:accept(Listen, infinity)},
        timer:sleep(infinity)
    end).

ports(Proc) ->
    {links, Links} = process_info(Proc, links),
    [P || P <- Links, is_port(P)].
