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
                                    fun ?MODULE:accept_error_closed_on_ssl_accept_test_/1,
                                    fun ?MODULE:send_and_recv_test_/1,
                                    fun ?MODULE:sendfile_and_recv_test_/1,
                                    fun ?MODULE:sendopts_test_/1,
                                    fun ?MODULE:conf_no_conflict_test_/1
                                   ]]}
     end}.

ranch_proxy_ssl_conf_test_() ->
    {setup,
     fun setup_ssl/0,
     fun teardown_ssl/1,
     fun(_) ->
             {foreach, fun setup_conf_test/0,
              fun teardown_conf_test/1,
              [{with, [T]} || T <- [fun ?MODULE:messages_test_/1,
                                    fun ?MODULE:secure_test_/1,
                                    fun ?MODULE:accept_and_connect_test_/1,
                                    fun ?MODULE:accept_error_closed_on_ssl_accept_test_/1,
                                    fun ?MODULE:send_and_recv_test_/1,
                                    fun ?MODULE:sendfile_and_recv_test_/1,
                                    fun ?MODULE:sendopts_test_/1,
                                    fun ?MODULE:conf_no_conflict_test_/1
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
    {_, CertSNI, KeySNI} = ct_helper:make_certs(),
    SNIFun = fun(_Hostname) -> [{cert,CertSNI},{key,KeySNI}] end,
    {ok, ListenProxySocket} = ranch_proxy_ssl:listen([{cert, Cert},
                                                      {key, Key},
                                                      {sni_fun, SNIFun}]),
    ListenPort = ranch_proxy_ssl:listen_port(ListenProxySocket),
    {ok, {Address, Port}} = inet:sockname(ListenPort),
    #{listen_socket => ListenProxySocket,
      address       => Address,
      port          => Port,
      cert          => Cert,
      key           => Key,
      sni_key       => KeySNI}.

teardown_test(_) ->
    ok.

setup_conf_test() ->
    {_, Cert, Key} = ct_helper:make_certs(),
    {_, CertSNI, KeySNI} = ct_helper:make_certs(),
    SNIFun = fun(_Hostname) -> [{cert,CertSNI},{key,KeySNI}] end,
    application:set_env(ranch_proxy_protocol, ssl_accept_opts,
                        [{cert, Cert},{key, Key}]),
    {ok, ListenProxySocket} = ranch_proxy_ssl:listen([{sni_fun, SNIFun}]),
    ListenPort = ranch_proxy_ssl:listen_port(ListenProxySocket),
    {ok, {Address, Port}} = inet:sockname(ListenPort),
    #{listen_socket => ListenProxySocket,
      address       => Address,
      port          => Port,
      cert          => Cert,
      key           => Key,
      sni_key       => KeySNI}.

teardown_conf_test(_) ->
    application:set_env(ranch_proxy_protocol, ssl_accept_opts, []),
    ok.

%% TESTS
messages_test_(_State) ->
    ?assertEqual(ranch_ssl:messages(), ranch_proxy_ssl:messages()).

secure_test_(_State) ->
    ?assertEqual(true, ranch_proxy_ssl:secure()).

% Listen on a socket, accept a connection and read the proxy protocol
% line. This tests is both for the accept and connect functions.
accept_and_connect_test_(State) ->
    % Setup a connection and return the sockets
    {AcceptProxySocket, _ConnectedProxySocket} = accept_and_connect(State),
    {ok, ProxyName} = ranch_proxy_ssl:proxyname(AcceptProxySocket),
    ?assertEqual({{{10,10,10,10},8888},
                  {{11,11,11,11},9999}}, ProxyName).

% Listens on a socket, connects to it with non-SSL ranch_proxy:connect,
% then closes when ssl:ssl_accept would be running to ensure a nice
% error is returned.
accept_error_closed_on_ssl_accept_test_(State) ->
    ?assertEqual({error, closed_on_ssl_accept}, accept_and_close(State)).

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

conf_no_conflict_test_(State=#{key := Key, sni_key := KeySNI}) ->
    {AcceptProxySocket, ConnectedProxySocket} = accept_and_connect_sni(State, "localhost"),
    % Send something
    Body = <<10,11>>,
    ?assertEqual(ok, ranch_proxy_ssl:send(ConnectedProxySocket, Body)),
    % Receive it on the other end
    ?assertEqual({ok, Body}, ranch_proxy_ssl:recv(AcceptProxySocket, 2,
                                              ?TEST_TIMEOUT)),
    ?assertEqual({ok,[{key, KeySNI}]},
                 ranch_proxy_ssl:ssl_connection_information(AcceptProxySocket, [key])),
    ?assertNotEqual({ok,[{key, Key}]},
                    ranch_proxy_ssl:ssl_connection_information(AcceptProxySocket, [key])).

% Internal
accept(ListenProxySocket) ->
    % Spawn the accept loop
    erlang:spawn(?MODULE, accept_loop, [ListenProxySocket, self()]),
    [{source_address, {10,10,10,10}},
     {source_port, 8888},
     {dest_address, {11,11,11,11}},
     {dest_port, 9999}].

accept_and_connect(#{listen_socket := ListenProxySocket,
                     address       := Address,
                     port          := Port,
                     cert          := Cert,
                     key           := Key}) ->
    ProxyOptions = accept(ListenProxySocket),

    % Connect to the server
    {ok, ConnectedProxySocket} = ranch_proxy_ssl:connect(Address, Port,
                                                         [{cert, Cert},
                                                          {key, Key}],
                                                         ProxyOptions),
    % Get the socket
    {ok, AcceptedProxySocket} = accept_socket(),
    {AcceptedProxySocket, ConnectedProxySocket}.

accept_and_connect_sni(#{listen_socket := ListenProxySocket,
                         address       := Address,
                         port          := Port,
                         cert          := Cert,
                         key           := Key}, Domain) ->
    ProxyOptions = accept(ListenProxySocket),

    % Connect to the server
    {ok, ConnectedProxySocket} = ranch_proxy_ssl:connect(Address, Port,
                                                         [{cert, Cert},
                                                          {key, Key},
                                                          {server_name_indication, Domain}],
                                                         ProxyOptions),
    % Get the socket
    {ok, AcceptedProxySocket} = accept_socket(),
    {AcceptedProxySocket, ConnectedProxySocket}.

accept_and_close(#{listen_socket := ListenProxySocket,
                   address       := Address,
                   port          := Port,
                   cert          := _,
                   key           := _}) ->
    ProxyOptions = accept(ListenProxySocket),

    {ok, ConnectedProxySocket} = ranch_proxy:connect(Address, Port, [], ProxyOptions),
    ok = ranch_proxy:close(ConnectedProxySocket),

    {error, closed_on_ssl_accept} = accept_socket().

accept_loop(ListenProxySocket, TestPid) ->
    case ranch_proxy_ssl:accept(ListenProxySocket, ?TEST_TIMEOUT) of
        {ok, AcceptedProxySocket} ->
            ok = ranch_proxy_ssl:controlling_process(AcceptedProxySocket, TestPid),
            TestPid ! {accepted_socket, AcceptedProxySocket};
        {error, Reason} ->
            TestPid ! {error, Reason}
    end.

accept_socket() ->
    receive
        {accepted_socket, AcceptedProxySocket} ->
            ranch_proxy_ssl:accept_ack(AcceptedProxySocket, ?TEST_TIMEOUT),
            {ok, AcceptedProxySocket};
        {error, Reason} ->
            {error, Reason}
    after ?TEST_TIMEOUT ->
            throw({error, 'timeout waiting for accept socket'})
    end.
