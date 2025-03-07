#! /bin/bash

# Firewall
xdpass firewall -i br1 --add --key 172.16.23.0/24
xdpass firewall -i br1 --list

# Redirect

## Tuntap
xdpass redirect tuntap -i br1 --add-tun tun0
xdpass redirect tuntap -i br1 --add-tap tap0,tap1
xdpass redirect tuntap -i br1 --list

## Spoof
xdpass redirect spoof -i br1 --add --src-ip 0.0.0.0/0 --dst-ip 0.0.0.0/0 --spoof-type icmp-echo-reply
xdpass redirect spoof -i br1 --add --src-ip 172.16.23.0/24 --dst-ip 172.16.23.0/24 --spoof-type icmp-echo-reply
xdpass redirect spoof -i br1 --add --src-ip 172.16.23.0/24 --dst-ip 172.16.23.0/24 --dst-port 80 --spoof-type tcp-reset
xdpass redirect spoof -i br1 --list