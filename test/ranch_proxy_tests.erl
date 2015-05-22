-module(ranch_proxy_tests).

-compile(export_all).

-include_lib("eunit/include/eunit.hrl").
-define(TEST_TIMEOUT, 1000).

ranch_proxy_test_() ->
    {foreach, fun setup/0, fun teardown/1,
     [{with, [T]} || T <- [fun ?MODULE:messages_test_/1,
                           fun ?MODULE:secure_test_/1,
                           fun ?MODULE:accept_and_connect_test_/1,
                           fun ?MODULE:send_and_recv_test_/1,
                           fun ?MODULE:sendfile_and_recv_test_/1,
                           fun ?MODULE:sendopts_test_/1]
     ]}.

setup() ->
    application:ensure_all_started(ranch),
    application:load(ranch_proxy_protocol),
    {ok, ListenProxySocket} = ranch_proxy:listen([]),
    ListenPort = ranch_proxy:listen_port(ListenProxySocket),
    {ok, {Address, Port}} = inet:sockname(ListenPort),
    #{listen_socket => ListenProxySocket,
      address => Address,
      port => Port}.

teardown(_) ->
    application:stop(ranch),
    application:unload(ranch_proxy_protocol).

%% TESTS
messages_test_(_State) ->
    ?assertEqual(ranch_tcp:messages(), ranch_proxy:messages()).

secure_test_(_State) ->
    ?assertEqual(false, ranch_proxy:secure()).

% Listen on a socket, accept a connection and read the proxy protocol
% line. This tests is borht for the accept and connect functions.
accept_and_connect_test_(#{listen_socket := ListenProxySocket,
                           address       := Address,
                           port          := Port}) ->
    % Setup a connection and return the sockets
    {AcceptProxySocket, _ConnectedProxySocket} =
        accept_and_connect(ListenProxySocket, Address, Port),
    {ok, ProxyName} = ranch_proxy:proxyname(AcceptProxySocket),
    ?assertEqual({{{10,10,10,10},8888},
                  {{11,11,11,11},9999}}, ProxyName).

send_and_recv_test_(#{listen_socket := ListenProxySocket,
                      address       := Address,
                      port          := Port}) ->
    {AcceptProxySocket, ConnectedProxySocket} =
        accept_and_connect(ListenProxySocket, Address, Port),
    % Send something
    Body = <<10,11>>,
    ?assertEqual(ok, ranch_proxy:send(ConnectedProxySocket, Body)),
    % Receive it on the other end
    ?assertEqual({ok, Body}, ranch_proxy:recv(AcceptProxySocket, 2,
                                              ?TEST_TIMEOUT)).

sendfile_and_recv_test_(#{listen_socket := ListenProxySocket,
                          address       := Address,
                          port          := Port}) ->
    {AcceptProxySocket, ConnectedProxySocket} =
        accept_and_connect(ListenProxySocket, Address, Port),
    ?assertMatch({ok, _}, ranch_proxy:sendfile(ConnectedProxySocket, ?FILE)),
    {ok, FileBody} = file:read_file(?FILE),
    ?assertEqual({ok, FileBody},
                 ranch_proxy:recv(AcceptProxySocket, size(FileBody),
                                  ?TEST_TIMEOUT)).

sendopts_test_(#{listen_socket := ListenProxySocket,
                 address       := Address,
                 port          := Port}) ->
    {AcceptProxySocket, _ConnectedProxySocket} =
        accept_and_connect(ListenProxySocket, Address, Port),
    ?assertEqual(ok, ranch_proxy:setopts(AcceptProxySocket,
                                         [{delay_send, true}])),
    AcceptPort = ranch_proxy:bearer_port(AcceptProxySocket),
    ?assertEqual({ok, [{delay_send, true}]},
                 inet:getopts(AcceptPort, [delay_send])).

% Internal
accept_and_connect(ListenProxySocket, Address, Port) ->
    % Spawn the accept loop
    erlang:spawn(?MODULE, accept_loop, [ListenProxySocket, self()]),
    ProxyOptions = [{source_address, {10,10,10,10}},
                    {source_port, 8888},
                    {dest_address, {11,11,11,11}},
                    {dest_port, 9999}],
    % Connect to the server
    {ok, ConnectedProxySocket} = ranch_proxy:connect(Address, Port, [],
                                                     ProxyOptions),
    % Get the socket
    {ok, AcceptedProxySocket} = accept_socket(),
    {AcceptedProxySocket, ConnectedProxySocket}.

accept_loop(ListenProxySocket, TestPid) ->
    {ok, AcceptedProxySocket} = ranch_proxy:accept(ListenProxySocket,
                                                   ?TEST_TIMEOUT),
    ok = ranch_proxy:controlling_process(AcceptedProxySocket, TestPid),
    TestPid ! {accepted_socket, AcceptedProxySocket}.

accept_socket() ->
    receive
        {accepted_socket, AcceptedProxySocket} ->
            ranch_proxy:accept_ack(AcceptedProxySocket, ?TEST_TIMEOUT),
            {ok, AcceptedProxySocket}
    after ?TEST_TIMEOUT ->
            throw({error, 'timeout waiting for accept socket'})
    end.
