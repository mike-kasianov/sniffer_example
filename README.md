# Sniffer Example

Simple sniffer written on Elixir using sockets.

Requires OTP version 22+

## Usage

Run iex:

```bash
iex sniffer.ex
```

Start the sniffer:

```elixir
> Sniffer.start_link([if_name: "wlp1s0", promiscuous: true])

> Sniffer.start_link([if_name: "wlp1s0"])

> Sniffer.start_link([])
```

## Permissions
Make sure you have permissions to parse raw packets and enable promiscuous mode.
It may require you to use `sudo` or set Linux capabilities:

```bash
setcap cap_net_raw,cap_net_admin=ep ERLANG_PATH/erts-VERSION/bin/beam.smp
```

## Promiscuous mode
When promiscuous mode is enabled by the sniffer it is not set back when application clesed. Make sure you turn it off manually:
```bash
ip link set wlp1s0 promisc off
```