#! /bin/bash

# Create a test environment with a bridge and two namespaces
# Each namespace has a veth pair connected to the bridge

# One bridge has $num_rx rx queues and $num_tx tx queues and $num_ns namespaces
num_br=2
num_rx=2
num_tx=2
num_ns=2

bridge_name() { echo br$1; }
netns_name() { echo ns$1$2; }
veth_name() { echo veth$1$2; }
netns_ip_addr() { echo 172.16.$((22 + $1)).$((1 + $2)); }

add_netns() {
    bridge_name=$(bridge_name $1)
    netns_name=$(netns_name $1 $2)
    veth_name=$(veth_name $1 $2)
    ip_addr=$(netns_ip_addr $1 $2)

    set -x
    ip netns add $netns_name
    ip link add $veth_name numrxqueues $num_rx numtxqueues $num_tx type veth peer name eth0 numrxqueues $num_rx numtxqueues $num_tx netns $netns_name
    ip link set $veth_name up
    ip link set $veth_name master $bridge_name
    ip netns exec $netns_name ip link set lo up
    ip netns exec $netns_name ip link set eth0 up
    ip netns exec $netns_name ip addr add $ip_addr/24 dev eth0
    set +x
}

del_netns() {
    netns_name=$(netns_name $1 $2)
    veth_name=$(veth_name $1 $2)

    set -x
    ip netns del $netns_name
    ip link del $veth_name
    set +x
}

add_bridge_netns() {
    bridge_name=$(bridge_name $1)

    # Setup bridge
    set -x
    ip link add $bridge_name numrxqueues $num_rx numtxqueues $num_tx type bridge
    ip link set $bridge_name up
    ip addr add $(netns_ip_addr $1 0)/24 dev $bridge_name
    set +x

    # Setup netns
    for i in $(seq 1 $num_ns); do
        add_netns $1 $i
    done
}

del_bridge_netns() {
    bridge_name=$(bridge_name $1)
    for i in $(seq 1 $num_ns); do
        del_netns $1 $i
    done
    set -x
    ip link del $bridge_name
    set +x
}

add() {
    # Setup bridge and netns
    for i in $(seq 1 $num_br); do
        add_bridge_netns $i
    done
}

del() {
    for i in $(seq 1 $num_br); do
        del_bridge_netns $i
    done
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
