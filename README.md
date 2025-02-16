# xdpass

Utilizing XDP for manipulating network packets in user mode.

## xdpass

A tool for interacting with **xdpassd** and performing packet sending benchmarks.

### benchmark

Construct packets based on command-line parameters for benchmark sending.

Construct packets with at least two parameters
1. *--interface*, special the interface for sending
2. *--dst-ip*, special the destination ip

Use the protocol( **icmp**, **tcp** and **udp**) as a subcommand, where different
subcommands correspond to specific protocol details, such as *--dst-port* for the **tcp** subcommand.

Additionally, use *--total* to specify the number of packets to send,
*--rate-limit* to control the sending rate, and *--stats* to enable sending statistics.

To get detailed usage of the commands mentioned, you can follow these commands:
```shell
$ xdpass bench --help
```

e.g.
To send 1000 packets to 127.0.0.1 via the lo interface at 10 packets per second.
```shell
$ xdpass bench icmp -i lo --dst-ip 127.0.0.1 -n 1000 --rate-limit 10 -s 1
```

### filter

To filter network packets by setting an IP or CIDR.

## xdpassd

Using XDP to filter or redirect packets to user space.
