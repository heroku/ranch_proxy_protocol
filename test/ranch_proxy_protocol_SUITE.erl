-module(ranch_proxy_protocol_SUITE).

-include_lib("common_test/include/ct.hrl").
-compile(export_all).

all() ->
    [ new_connection, proxy_connect,
      reuse_socket ].

init_per_suite(Config) ->
    application:ensure_all_started(ranch),
    Config.

init_per_testcase(new_connection, Config) ->
    Port = 9401,
    {ok, Pid} = ranch:start_listener(ranch_proxy_protocol_acceptor,
                                     1,
                                     ranch_proxy_transport,
                                     [{port, Port}],
                                     ranch_proxy_protocol_test_protocol, [{tester, self()}]),
    [{port, Port},
     {listeners, Pid} | Config];
init_per_testcase(proxy_connect, Config) ->
    Port = 9401,
    {ok, Pid} = ranch:start_listener(ranch_proxy_protocol_acceptor,
                                     1,
                                     ranch_proxy_transport,
                                     [{port, Port}],
                                     ranch_proxy_protocol_test_protocol, [{tester, self()}]),
    [{port, Port},
     {listeners, Pid} | Config];
init_per_testcase(reuse_socket, Config) ->
    Port = 9401,
    {ok, Pid} = ranch:start_listener(ranch_proxy_protocol_acceptor,
                                     1,
                                     ranch_proxy_transport,
                                     [{port, Port}],
                                     ranch_proxy_protocol_test_protocol, [{tester, self()}]),
    [{port, Port},
     {listeners, Pid} | Config].

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
        Proplist ->
            {192,168,1,1} = proplists:get_value(source_address, Proplist),
            {192,168,1,2} = proplists:get_value(dest_address, Proplist),
            80 = proplists:get_value(source_port, Proplist),
            81 = proplists:get_value(dest_port, Proplist)
    end,
    Config.

proxy_connect(Config) ->
    Port = ?config(port, Config),
    {ok, _Socket} = ranch_proxy_transport:connect({127,0,0,1}, Port, [],
                                                  [{inet_version, ipv4},
                                                   {source_address, {192,168,0,3}},
                                                   {dest_address, {192,168,0,4}},
                                                   {source_port, 82},
                                                   {dest_port, 83}]),
    receive
        Proplist ->
            {192,168,0,3} = proplists:get_value(source_address, Proplist),
            {192,168,0,4} = proplists:get_value(dest_address, Proplist),
            82 = proplists:get_value(source_port, Proplist),
            83 = proplists:get_value(dest_port, Proplist)
    end,
    Config.

reuse_socket(Config) ->
    Port = ?config(port, Config),
    {ok, Socket} = ranch_proxy_transport:connect({127,0,0,1}, Port, [],
                                                 [{inet_version, ipv4},
                                                  {source_address, {192,168,0,3}},
                                                  {dest_address, {192,168,0,4}},
                                                  {source_port, 82},
                                                  {dest_port, 83}]),
    receive
        Proplist ->
            {192,168,0,3} = proplists:get_value(source_address, Proplist),
            {192,168,0,4} = proplists:get_value(dest_address, Proplist),
            82 = proplists:get_value(source_port, Proplist),
            83 = proplists:get_value(dest_port, Proplist)
    end,
    ranch_proxy_protocol:close(Socket),
    {ok, Socket1} = ranch_proxy_transport:connect({127,0,0,1}, Port, [],
                                                  [{inet_version, ipv4},
                                                   {source_address, {192,168,0,5}},
                                                   {dest_address, {192,168,0,6}},
                                                   {source_port, 84},
                                                   {dest_port, 85}]),
    receive
        Proplist1 ->
            {192,168,0,5} = proplists:get_value(source_address, Proplist1),
            {192,168,0,6} = proplists:get_value(dest_address, Proplist1),
            84 = proplists:get_value(source_port, Proplist1),
            85 = proplists:get_value(dest_port, Proplist1)
    end,
    ranch_proxy_transport:close(Socket1),
    Config.
