-module(ranch_proxy).
-behaviour(ranch_transport).

-record(proxy_socket, { lsocket :: inet:socket(),
                        csocket :: inet:socket(),
                        opts :: ranch_tcp:opts(),
                        inet_version :: ipv4|ipv6,
                        source_address :: inet:ip_address(),
                        dest_address :: inet:ip_address(),
                        source_port :: inet:port_number(),
                        dest_port :: inet:port_number()}).

-export([name/0]).
-export([secure/0]).
-export([messages/0]).
-export([match_port/1]).
-export([listen/1]).
-export([accept/2]).
-export([accept_ack/2]).
-export([connect/3]).
-export([connect/4]).
-export([recv/3]).
-export([send/2]).
-export([sendfile/2]).
-export([sendfile/4]).
-export([sendfile/5]).
-export([setopts/2]).
-export([controlling_process/2]).
-export([peername/1]).
-export([proxyname/1]).
-export([sockname/1]).
-export([shutdown/2]).
-export([close/1]).

-export([opts_from_socket/2]).
-export([bearer_port/1]).

-type proxy_opts() :: [{source_address, inet:ip_address()} |
                       {source_port, inet:port_number()} |
                       {dest_address, inet:ip_address()} |
                       {source_port, inet:port_number()}].

-opaque proxy_socket() :: #proxy_socket{}.
-type proxy_protocol_info() :: {{inet:ip_address(), inet:port_number()},
                                {inet:ip_address(), inet:port_number()}}.
-export_type([proxy_opts/0,
              proxy_socket/0,
              proxy_protocol_info/0]).

-define(DEFAULT_PROXY_TIMEOUT, config(proxy_protocol_timeout)).

name() -> proxy_protocol_tcp.

-spec secure() -> false.
secure() -> false.

messages() -> ranch_tcp:messages().

-spec match_port(proxy_socket()) -> port().
match_port(#proxy_socket{csocket=Port}) when is_port(Port) -> Port.

-spec listen(ranch_tcp:opts()) -> {ok, proxy_socket()} | {error, atom()}.
listen(Opts) ->
    case ranch_tcp:listen(Opts) of
        {ok, LSocket} ->
            {ok, #proxy_socket{lsocket = LSocket,
                               opts = Opts}};
        {error, Error} ->
            {error, Error}
    end.

-spec accept(proxy_socket(), timeout())
            -> {ok, proxy_socket()} | {error, closed | timeout | not_proxy_protocol |
                                       {timeout, proxy_handshake} | atom()}.
accept(#proxy_socket{lsocket = LSocket,
                     opts = Opts}, Timeout) ->
    Started = os:timestamp(),
    case ranch_tcp:accept(LSocket, Timeout) of
        {ok, CSocket} ->
            NextWait = get_next_timeout(Started, os:timestamp(), Timeout),
            ProxySocket = #proxy_socket{ lsocket = LSocket,
                                         csocket = CSocket,
                                         opts = Opts },
            ok = setopts(ProxySocket, [{active, once}, {packet, line}]),
            receive
                {_, CSocket, <<"PROXY ", ProxyInfo/binary>>} ->
                    case parse_proxy_protocol(ProxyInfo) of
                        {InetVersion, SourceAddress, DestAddress, SourcePort, DestPort} ->
                            reset_socket_opts(ProxySocket, Opts),
                            {ok, ProxySocket#proxy_socket{inet_version = InetVersion,
                                                          source_address = SourceAddress,
                                                          dest_address = DestAddress,
                                                          source_port = SourcePort,
                                                          dest_port = DestPort}};
                        unknown_peer ->
                            reset_socket_opts(ProxySocket, Opts),
                            {ok, ProxySocket};
                        not_proxy_protocol ->
                            close(ProxySocket),
                            {error, not_proxy_protocol}
                    end;
                Other ->
                    close(ProxySocket),
                    {error, Other}
            after NextWait ->
                    close(ProxySocket),
                    {error, {timeout, proxy_handshake}}
            end;
        {error, Error} ->
            {error, Error}
    end.

-spec accept_ack(proxy_socket(), timeout()) -> ok.
accept_ack(_ProxySocket, _Timeout) ->
    ok.

-spec connect(inet:ip_address() | inet:hostname(),
              inet:port_number(), any())
             -> {ok, proxy_socket()} | {error, atom()}.
connect(Host, Port, Opts) when is_integer(Port) ->
    connect(Host, Port, Opts, []).

-spec connect(inet:ip_address() | inet:hostname(),
              inet:port_number(), any(), proxy_opts())
             -> {ok, proxy_socket()} | {error, atom()}.
connect(Host, Port, Opts, ProxyOpts) when is_integer(Port) ->
    case ranch_tcp:connect(Host, Port, Opts) of
        {ok, Socket} ->
            ProxySocket = #proxy_socket{csocket = Socket},
            SourceAddress = proplists:get_value(source_address, ProxyOpts),
            DestAddress = proplists:get_value(dest_address, ProxyOpts),
            SourcePort = proplists:get_value(source_port, ProxyOpts),
            DestPort = proplists:get_value(dest_port, ProxyOpts),
            case create_proxy_protocol_header(SourceAddress, DestAddress, SourcePort, DestPort) of
                {ok, ProxyHeader} ->
                    ranch_tcp:send(Socket, ProxyHeader),
                    {ok, ProxySocket#proxy_socket{source_address = SourceAddress,
                                                  dest_address = DestAddress,
                                                  source_port = SourcePort,
                                                  dest_port = DestPort}};
                {error, invalid_proxy_information} ->
                    ranch_tcp:send(Socket, <<"PROXY UNKNOWN\r\n">>),
                    {ok, #proxy_socket{csocket = Socket}}
            end;
        {error, Error} ->
            {error, Error}
    end.

-spec recv(proxy_socket(), non_neg_integer(), timeout())
          -> {ok, any()} | {error, closed | atom()}.
recv(#proxy_socket{csocket=Socket}, Length, Timeout) ->
    ranch_tcp:recv(Socket, Length, Timeout).

-spec send(proxy_socket(), iodata()) -> ok | {error, atom()}.
send(#proxy_socket{csocket=Socket}, Packet) ->
    ranch_tcp:send(Socket, Packet).

-spec sendfile(proxy_socket(), file:name_all())
              -> {ok, non_neg_integer()} | {error, atom()}.
sendfile(Socket, Filename) ->
    sendfile(Socket, Filename, 0, 0, []).

-spec sendfile(proxy_socket(), file:name_all() | file:fd(), non_neg_integer(),
               non_neg_integer())
              -> {ok, non_neg_integer()} | {error, atom()}.
sendfile(Socket, File, Offset, Bytes) ->
    sendfile(Socket, File, Offset, Bytes, []).

-spec sendfile(proxy_socket(), file:name_all() | file:fd(), non_neg_integer(),
               non_neg_integer(), [{chunk_size, non_neg_integer()}])
              -> {ok, non_neg_integer()} | {error, atom()}.
sendfile(#proxy_socket{csocket=Socket}, Filename, Offset, Bytes, Opts) ->
    ranch_tcp:sendfile(Socket, Filename, Offset, Bytes, Opts).

-spec setopts(proxy_socket(), list()) -> ok | {error, atom()}.
setopts(#proxy_socket{csocket=Socket}, Opts) ->
    ranch_tcp:setopts(Socket, Opts).

-spec controlling_process(proxy_socket(), pid())
                         -> ok | {error, closed | not_owner | atom()}.
controlling_process(#proxy_socket{csocket=Socket}, Pid) ->
    ranch_tcp:controlling_process(Socket, Pid).

-spec peername(proxy_socket())
              -> {ok, {inet:ip_address(), inet:port_number()}} | {error, atom()}.
peername(#proxy_socket{csocket=Socket}) ->
    ranch_tcp:peername(Socket).

-spec proxyname(proxy_socket()) -> 
                       {ok, proxy_protocol_info()}.
proxyname(#proxy_socket{source_address = SourceAddress,
                        dest_address = DestAddress,
                        source_port = SourcePort,
                        dest_port = DestPort}) ->
    {ok, {{SourceAddress, SourcePort}, {DestAddress, DestPort}}}.

-spec sockname(proxy_socket())
              -> {ok, {inet:ip_address(), inet:port_number()}} | {error, atom()}.
sockname(#proxy_socket{lsocket = Socket}) ->
    ranch_tcp:sockname(Socket).

-spec shutdown(proxy_socket(), read|write|read_write)
              -> ok | {error, atom()}.
shutdown(#proxy_socket{csocket=Socket}, How) ->
    ranch_tcp:shutdown(Socket, How).

-spec close(proxy_socket()) -> ok.
close(#proxy_socket{csocket=Socket}) ->
    ranch_tcp:close(Socket).

% Internal
create_proxy_protocol_header(SourceAddress, DestAddress, SourcePort, DestPort) when is_tuple(SourceAddress),
                                                                                    is_tuple(DestAddress),
                                                                                    is_integer(SourcePort),
                                                                                    is_integer(DestPort) ->
    Proto = get_protocol(SourceAddress, DestAddress),
    SourceAddressStr = inet_parse:ntoa(SourceAddress),
    DestAddressStr = inet_parse:ntoa(DestAddress),
    SourcePortString = integer_to_list(SourcePort),
    DestPortString = integer_to_list(DestPort),
    create_proxy_protocol_header(Proto, SourceAddressStr, DestAddressStr, SourcePortString, DestPortString).

create_proxy_protocol_header(ipv4, SourceAddress, DestAddress, SourcePort, DestPort) ->
    {ok, io_lib:format("PROXY TCP4 ~s ~s ~s ~s\r\n", [SourceAddress, DestAddress, SourcePort, DestPort])};
create_proxy_protocol_header(ipv6, SourceAddress, DestAddress, SourcePort, DestPort) ->
    {ok, io_lib:format("PROXY TCP6 ~s ~s ~s ~s\r\n", [SourceAddress, DestAddress, SourcePort, DestPort])};
create_proxy_protocol_header(_, _, _, _, _) ->
    {error, invalid_proxy_information}.

get_protocol(SourceAddress, DestAddress) when tuple_size(SourceAddress) =:= 8,
                                              tuple_size(DestAddress) =:= 8 ->
    ipv6;
get_protocol(SourceAddress, DestAddress) when tuple_size(SourceAddress) =:= 4,
                                              tuple_size(DestAddress) =:= 4 ->
    ipv4.

parse_proxy_protocol(<<"TCP", Proto:1/binary, _:1/binary, Info/binary>>) ->
    InfoStr = binary_to_list(Info),
    case string:tokens(InfoStr, " \r\n") of
        [SourceAddress, DestAddress, SourcePort, DestPort] ->
            case {parse_inet(Proto), parse_ips([SourceAddress, DestAddress], []),
                  parse_ports([SourcePort, DestPort], [])} of
                {ProtoParsed, [SourceInetAddress, DestInetAddress], [SourceInetPort, DestInetPort]} ->
                    {ProtoParsed, SourceInetAddress, DestInetAddress, SourceInetPort, DestInetPort};
                _ ->
                    malformed_proxy_protocol
            end
    end;
parse_proxy_protocol(<<"UNKNOWN", _/binary>>) ->
    unknown_peer;
parse_proxy_protocol(_) ->
    not_proxy_protocol.

parse_inet(<<"4">>) ->
    ipv4;
parse_inet(<<"6">>) ->
    ipv6;
parse_inet(_) ->
    {error, invalid_inet_version}.

parse_ports([], Retval) ->
    Retval;
parse_ports([Port|Ports], Retval) ->
    try list_to_integer(Port) of
        IntPort ->
            parse_ports(Ports, Retval++[IntPort])
    catch
        error:badarg ->
            {error, invalid_port}
    end.

parse_ips([], Retval) ->
    Retval;
parse_ips([Ip|Ips], Retval) ->
    case inet:parse_address(Ip) of
        {ok, ParsedIp} ->
            parse_ips(Ips, Retval++[ParsedIp]);
        _ ->
            {error, invalid_address}
    end.

reset_socket_opts(ProxySocket, Opts) ->
    Opts2 = ranch:filter_options(Opts, [active,buffer,delay_send,deliver,dontroute,
                                        exit_on_close,header,high_msgq_watermark,
                                        high_watermark,keepalive,linger,low_msgq_watermark,
                                        low_watermark,mode,nodelay,packet,packet_size,priority,
                                        recbuf,reuseaddr,send_timeout,send_timeout_close,sndbuf,tos],
                                 [binary, {active, false}, {packet, raw},
                                  {reuseaddr, true}, {nodelay, true}]),
    setopts(ProxySocket, Opts2).

get_next_timeout(_, _, infinity) ->
    %% Never leave `infinity' in place. This may be valid for socket
    %% accepts, but is fairly dangrous and risks causing lockups when
    %% the data over the socket is bad or invalid.
    ?DEFAULT_PROXY_TIMEOUT;
get_next_timeout(T1, T2, Timeout) ->
    TimeUsed = round(timer:now_diff(T2, T1) / 1000),
    erlang:max(?DEFAULT_PROXY_TIMEOUT, Timeout - TimeUsed).

opts_from_socket(Transport, Socket) ->
    case {source_from_socket(Transport, Socket),
          dest_from_socket(Transport, Socket)} of
        {{ok, Src}, {ok, Dst}} ->
            {ok, Src ++ Dst};
        {{error, _} = Err, _} -> Err;
        {_, {error, _} = Err} -> Err
    end.

source_from_socket(Transport, Socket) ->
    case Transport:peername(Socket) of
        {ok, {Addr, Port}} ->
            {ok, [{source_address, Addr},
                  {source_port, Port}]};
        Err -> Err
    end.

dest_from_socket(Transport, Socket) ->
    case Transport:sockname(Socket) of
        {ok, {Addr, Port}} ->
            {ok, [{dest_address, Addr},
                  {dest_port, Port}]};
        Err -> Err
    end.

bearer_port(#proxy_socket{csocket = Port}) -> Port.

config(Key) ->
    {ok, Val} = application:get_env(ranch_proxy_protocol, Key),
    Val.
