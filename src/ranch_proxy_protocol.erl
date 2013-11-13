-module(ranch_proxy_protocol).
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
-export([messages/0]).
-export([listen/1]).
-export([accept/2]).
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
-export([close/1]).

-type proxy_opts() :: [{inet_version, ipv4 | ipv6} |
                       {source_address, inet:ip_address() | inet:hostname()} |
                       {source_port, inet:port_number()} |
                       {dest_address, inet:ip_address() | inet:hostname()} |
                       {source_port, inet:port_number()}].
-opaque proxy_socket() :: #proxy_socket{}.
-type proxy_protocol_info() :: [{source_address, inet:ip_address()} |
                                {dest_address, inet:ip_address()} |
                                {source_port, inet:port_number()} |
                                {dest_port, inet:port_number()}].
-export_type([proxy_opts/0,
              proxy_socket/0,
              proxy_protocol_info/0]).

name() -> proxy_protocol_tcp.

messages() -> ranch_tcp:messages().

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
            -> {ok, proxy_socket()} | {error, closed | timeout | not_proxy_protocol | atom()}.
accept(#proxy_socket{lsocket = LSocket,
                     opts = Opts}, Timeout) ->
    case ranch_tcp:accept(LSocket, Timeout) of 
        {ok, CSocket} ->
            ProxySocket = #proxy_socket{ lsocket = LSocket,
                                         csocket = CSocket,
                                         opts = Opts },
            ok = setopts(ProxySocket, [{active, once}, {packet, line}]),
            receive
                {_, _Sock, <<"PROXY ", ProxyInfo/binary>>} ->
                    case parse_proxy_protocol(ProxyInfo) of
                        {InetVersion, SourceAddress, DestAddress, SourcePort, DestPort} ->
                            setopts(ProxySocket, ranch:filter_options(Opts, [backlog, ip, nodelay, port, raw],
                                                                      [binary, {active, false}, {packet, raw},
                                                                       {reuseaddr, true}, {nodelay, true}])),
                            {ok, ProxySocket#proxy_socket{inet_version = InetVersion,
                                                          source_address = SourceAddress,
                                                          dest_address = DestAddress,
                                                          source_port = SourcePort,
                                                          dest_port = DestPort}};
                        unknown_peer ->
                            setopts(ProxySocket, ranch:filter_options(Opts, [backlog, ip, nodelay, port, raw],
                                                                      [binary, {active, false}, {packet, raw},
                                                                       {reuseaddr, true}, {nodelay, true}])),
                                {ok, ProxySocket};
                        not_proxy_protocol ->
                            {error, not_proxy_protocol}
                    end;
                Other ->
                    {error, Other}
            after 5000 ->
                    {error, timeout}
            end;
        {error, Error} ->
            {error, Error}
    end.

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
            Protocol = proplists:get_value(inet_version, ProxyOpts),
            SourceAddress = proplists:get_value(source_address, ProxyOpts),
            DestAddress = proplists:get_value(dest_address, ProxyOpts),
            SourcePort = proplists:get_value(source_port, ProxyOpts),
            DestPort = proplists:get_value(dest_port, ProxyOpts),
            case create_proxy_protocol_header(Protocol, SourceAddress, DestAddress, SourcePort, DestPort) of
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
                       {ok, proxy_protocol_info()} | {error, atom()}.
proxyname(#proxy_socket{source_address = SourceAddress,
                        dest_address = DestAddress,
                        source_port = SourcePort,
                        dest_port = DestPort}) ->
    {ok, [{source_address, SourceAddress},
          {dest_address, DestAddress},
          {source_port, SourcePort},
          {dest_port, DestPort}]}.

-spec sockname(proxy_socket())
              -> {ok, {inet:ip_address(), inet:port_number()}} | {error, atom()}.
sockname(#proxy_socket{lsocket = Socket}) ->
    ranch_tcp:sockname(Socket).

-spec close(proxy_socket()) -> ok.
close(#proxy_socket{csocket=Socket}) ->
    ranch_tcp:close(Socket).

% Internal
create_proxy_protocol_header(Proto, SourceAddress, DestAddress, SourcePort, DestPort) when is_tuple(SourceAddress),
                                                                                           is_tuple(DestAddress),
                                                                                           is_integer(SourcePort),
                                                                                           is_integer(DestPort) ->
    SourceAddressStr = inet_parse:ntoa(SourceAddress),
    DestAddressStr = inet_parse:ntoa(DestAddress),
    SourcePortString = integer_to_list(SourcePort),
    DestPortString = integer_to_list(DestPort),
    create_proxy_protocol_header(Proto, SourceAddressStr, DestAddressStr, SourcePortString, DestPortString);
create_proxy_protocol_header(ipv4, SourceAddress, DestAddress, SourcePort, DestPort) ->
    {ok, io_lib:format("PROXY TCP4 ~s ~s ~s ~s\r\n", [SourceAddress, DestAddress, SourcePort, DestPort])};
create_proxy_protocol_header(ipv6, SourceAddress, DestAddress, SourcePort, DestPort) ->
    {ok, io_lib:format("PROXY TCP6 ~s ~s ~s ~s\r\n", [SourceAddress, DestAddress, SourcePort, DestPort])};
create_proxy_protocol_header(_, _, _, _, _) ->
    {error, invalid_proxy_information}.

parse_proxy_protocol(<<"TCP", Proto:1/binary, _:1/binary, Info/binary>>) ->
    InfoStr= binary_to_list(Info),
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
