-module(ranch_proxy_protocol_test_protocol).

-export([start_link/4,
         init/4]).

start_link(Ref, Socket, Transport, Opts) ->
    Pid = spawn_link(?MODULE, init, [Ref, Socket, Transport, Opts]),
    {ok, Pid}.

init(Ref, Socket, Transport, Opts) ->
    ok = ranch:accept_ack(Ref),
    Tester = proplists:get_value(tester, Opts),
    {ok, ProxyInfo} = Transport:proxyname(Socket),
    Tester ! ProxyInfo,
    loop(Socket, Transport).

loop(_Socket, _Transport) ->
    ok.
