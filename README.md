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

Additionally, use
- *--queue-id -q* to specify the queue id
- *--total -n* to specify the number of packets to send
- *--batch -b* to specify the batch size when *--rate-limit* is -1
- *--rate-limit -r* to control the sending rate
- *--rate-limit-prec -p* to specify the rate limit precision
- *--stats-dur -s* to enable sending statistics
- *--cores -c* to specify the cpu cores

For *--xdp-copy* and *--xdp-zero-copy* options:
> Some drivers require specifying the use of copy mode to consume TX data.
> Similarly, these drivers may only support loading XDP programs in generic mode.

To get detailed usage of the commands mentioned, you can follow these commands:
```shell
$ xdpass bench --help
```

#### examples

To send udp packets to 127.0.0.1 via the *lo* interface unlimited rate and tx packets.
```shell
$ xdpass bench udp -i lo --dst-ip 127.0.0.1 -s 1
```

To send 1000 icmp packets to 127.0.0.1 via the *lo* interface at 10 packets per second.
```shell
$ xdpass bench icmp -i lo --dst-ip 127.0.0.1 -n 1000 -r 10 -s 1
```

To send tcp packets to 127.0.0.1 via the *lo* interface unlimited rate and tx packets.
Specify the source port and destination port and tcp flags.
```shell
$ xdpass bench tcp -i lo --dst-ip 127.0.0.1 --src-port 1234 --dst-port 1234 --SYN -s 1
```

Specify complete network parameters
```shell
$ xdpass bench tcp -i br1 --src-mac 6a:10:e9:37:63:ac --dst-mac 72:18:fd:f4:fa:b8 \
    --src-ip 172.16.23.1 --dst-ip 172.16.23.2 \
    --src-port 1234 --dst-port 1234 --PSH --ACK --seq 1234567890 --payload "hello"
```

Then you can see the statistics output (with *-s 1*)
```txt
| QUEUE | TX PKTS | TX PPS |   TX BYTES   |    TX BPS     | TX IOPS | TX ERR IOPS |
+-------+---------+--------+--------------+---------------+---------+-------------+
|     0 |  720896 | 179933 |  46.9 MBytes |  93.6 MBits/s |    5615 |           0 |
|     1 |  720896 | 179997 |  46.9 MBytes |  93.6 MBits/s |    5612 |           0 |
|     2 |  720896 | 179997 |  46.9 MBytes |  93.6 MBits/s |    5612 |           0 |
|     3 |  720896 | 179996 |  46.9 MBytes |  93.6 MBits/s |    5612 |           0 |
|   SUM | 2883584 | 719924 | 187.4 MBytes | 374.4 MBits/s |   22451 |           0 |
```

### filter

To filter network packets by setting an IP or CIDR.

## xdpassd

Using XDP to filter or redirect packets to user space.

## scripts

### make_test_env.sh

Create a environment with a bridge and two namespaces for testing.

```shell
$ ./scripts/make_test_env.sh add
```
