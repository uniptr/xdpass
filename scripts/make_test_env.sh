#! /bin/bash

# Create a test environment with a bridge and two namespaces
# Each namespace has a veth pair connected to the bridge

# The bridge has $num_rx rx queues and $num_tx tx queues and $num_ns namespaces
num_rx=4
num_tx=4
num_ns=4

add_netns() {
    netns_name=ns$1
    ip netns add $netns_name
    ip link add veth$1 numrxqueues $num_rx numtxqueues $num_tx type veth peer name eth0 numrxqueues $num_rx numtxqueues $num_tx netns $netns_name
    ip link set veth$1 up
    ip link set veth$1 master br1
    ip netns exec $netns_name ip link set lo up
    ip netns exec $netns_name ip link set eth0 up
    ip netns exec $netns_name ip addr add 172.16.23.$((1 + $1))/24 dev eth0
}

del_netns() {
    ip netns del ns$1
    ip link del veth$1
}

add() {
    set -x

    # Setup bridge
    ip link add br1 numrxqueues $num_rx numtxqueues $num_tx type bridge
    ip link set br1 up
    ip addr add 172.16.23.1/24 dev br1

    # Setup netns
    for i in $(seq 1 $num_ns); do
        add_netns $i
    done
}

del() {
    set -x

    for i in $(seq 1 $num_ns); do
        del_netns $i
    done
    ip link del br1
}

case $1 in
add)
    add
    ;;
del)
    del
    ;;
*)
    echo "Usage: $0 add|del"
    ;;
esac
