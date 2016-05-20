# Ranch Proxy Protocol Socket

This module wraps the `ranch_tcp` module to parse the
[proxy protocol](http://haproxy.1wt.eu/download/1.5/doc/proxy-protocol.txt)
(version 1) before handing the socket on to the `ranch` handler.

It has the same API as the `ranch_tcp` module but with two new
functions; `connect/4` and `proxyname/1`.

The transport is called `ranch_proxy`.

## `connect/4`

`connect/4` allows you to connect with to a remote host, and sending
the proxy protocol header automatically before going on to use the
socket. It's similar to the regular `ranch_tcp:connect/3` but accepts
a third tuple containing proxy protocol information:

``` erlang
-type proxy_opts() :: [{inet_version, ipv4 | ipv6} |
                       {source_address, inet:ip_address() | inet:hostname()} |
                       {source_port, inet:port_number()} |
                       {dest_address, inet:ip_address() | inet:hostname()} |
                       {source_port, inet:port_number()}].
-spec connect(inet:ip_address() | inet:hostname(),
              inet:port_number(), any(), proxy_opts())
	-> {ok, #proxy_socket{}} | {error, atom()}.
```

## `proxyname/1`

`proxyname/1` gives you the proxy protocol information:

``` erlang
-type proxy_protocol_info() :: [{source_address, inet:ip_address()} |
                                {dest_address, inet:ip_address()} |
                                {source_port, inet:port_number()} |
                                {dest_port, inet:port_number()}].
-spec proxyname(proxy_socket()) ->
                       {ok, proxy_protocol_info()} | {error, atom()}.
```

# Run the tests!

Sure why don't you

``` bash
$ rebar3 ct
```

# License

See the `LICENSE` file.
