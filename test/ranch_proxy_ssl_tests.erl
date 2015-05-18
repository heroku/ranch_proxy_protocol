-module(ranch_proxy_ssl_tests).

-compile(export_all).

-include_lib("eunit/include/eunit.hrl").
-define(TEST_TIMEOUT, 1000).

ranch_proxy_ssl_test_() ->
    {setup,
     fun setup_ssl/0,
     fun teardown_ssl/1,
     fun(_) ->
             {foreach, fun setup_test/0,
              fun teardown_test/1,
              [{with, [T]} || T <- [fun ?MODULE:messages_test_/1,
                                    fun ?MODULE:secure_test_/1,
                                    fun ?MODULE:accept_and_connect_test_/1,
                                    fun ?MODULE:send_and_recv_test_/1,
                                    fun ?MODULE:sendfile_and_recv_test_/1,
                                    fun ?MODULE:sendopts_test_/1
                                   ]]}
     end}.

setup_ssl() ->
    {ok, SSLStarted} = application:ensure_all_started(ssl),
    {ok, RanchStarted} = application:ensure_all_started(ranch),
    application:load(ranch_proxy_protocol),
    SSLStarted ++ RanchStarted.

teardown_ssl(Apps) ->
    application:unload(ranch_proxy_protocol),
    [application:stop(App) || App <- Apps].

setup_test() ->
    {_, Cert, Key} = ct_helper:make_certs(),
    {ok, ListenProxySocket} = ranch_proxy_ssl:listen([{cert, Cert},
                                                      {key, Key}]),
    ListenPort = ranch_proxy_ssl:listen_port(ListenProxySocket),
    {ok, {Address, Port}} = inet:sockname(ListenPort),
    #{listen_socket => ListenProxySocket,
      address       => Address,
      port          => Port,
      cert          => Cert,
      key           => Key}.

teardown_test(_) ->
    ok.

%% TESTS
messages_test_(_State) ->
    ?assertEqual(ranch_ssl:messages(), ranch_proxy_ssl:messages()).

secure_test_(_State) ->
    ?assertEqual(true, ranch_proxy_ssl:secure()).

% Listen on a socket, accept a connection and read the proxy protocol
% line. This tests is borht for the accept and connect functions.
accept_and_connect_test_(State) ->
    % Setup a connection and return the sockets
    {AcceptProxySocket, _ConnectedProxySocket} = accept_and_connect(State),
    {ok, ProxyName} = ranch_proxy_ssl:proxyname(AcceptProxySocket),
    ?assertEqual({{{10,10,10,10},8888},
                  {{11,11,11,11},9999}}, ProxyName).

send_and_recv_test_(State) ->
    {AcceptProxySocket, ConnectedProxySocket} = accept_and_connect(State),
    % Send something
    Body = <<10,11>>,
    ?assertEqual(ok, ranch_proxy_ssl:send(ConnectedProxySocket, Body)),
    % Receive it on the other end
    ?assertEqual({ok, Body}, ranch_proxy_ssl:recv(AcceptProxySocket, 2,
                                              ?TEST_TIMEOUT)).

sendfile_and_recv_test_(State) ->
    {AcceptProxySocket, ConnectedProxySocket} = accept_and_connect(State),
    ?assertMatch({ok, _}, ranch_proxy_ssl:sendfile(ConnectedProxySocket, ?FILE)),
    {ok, FileBody} = file:read_file(?FILE),
    ?assertEqual({ok, FileBody},
                 ranch_proxy_ssl:recv(AcceptProxySocket, size(FileBody),
                                      ?TEST_TIMEOUT)).

sendopts_test_(State) ->
    {AcceptProxySocket, _ConnectedProxySocket} = accept_and_connect(State),
    ?assertEqual(ok, ranch_proxy_ssl:setopts(AcceptProxySocket,
                                         [{delay_send, true}])),
    AcceptPort = ranch_proxy_ssl:bearer_port(AcceptProxySocket),
    ?assertEqual({ok, [{delay_send, true}]},
                 ssl:getopts(AcceptPort, [delay_send])).

% Internal
accept_and_connect(#{listen_socket := ListenProxySocket,
                     address       := Address,
                     port          := Port,
                     cert          := Cert,
                     key           := Key}) ->
    % Spawn the accept loop
    erlang:spawn(?MODULE, accept_loop, [ListenProxySocket, self()]),
    ProxyOptions = [{source_address, {10,10,10,10}},
                    {source_port, 8888},
                    {dest_address, {11,11,11,11}},
                    {dest_port, 9999}],
    % Connect to the server
    {ok, ConnectedProxySocket} = ranch_proxy_ssl:connect(Address, Port,
                                                         [{cert, Cert},
                                                          {key, Key}],
                                                         ProxyOptions),
    % Get the socket
    {ok, AcceptedProxySocket} = accept_socket(),
    {AcceptedProxySocket, ConnectedProxySocket}.

accept_loop(ListenProxySocket, TestPid) ->
    {ok, AcceptedProxySocket} = ranch_proxy_ssl:accept(ListenProxySocket,
                                                       ?TEST_TIMEOUT),
    ok = ranch_proxy_ssl:controlling_process(AcceptedProxySocket, TestPid),
    TestPid ! {accepted_socket, AcceptedProxySocket}.

accept_socket() ->
    receive
        {accepted_socket, AcceptedProxySocket} ->
            ranch_proxy_ssl:accept_ack(AcceptedProxySocket, ?TEST_TIMEOUT),
            {ok, AcceptedProxySocket}
    after ?TEST_TIMEOUT ->
            throw({error, 'timeout waiting for accept socket'})
    end.
