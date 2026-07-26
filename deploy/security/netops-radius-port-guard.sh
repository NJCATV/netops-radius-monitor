#!/bin/sh
set -eu

# 213 Radius node: protect published service ports without changing the
# default policy, SSH listener, capture traffic, or unrelated services.
ensure() { iptables -C INPUT "$@" 2>/dev/null || iptables -I INPUT 1 "$@"; }

# Insert from lowest to highest priority because missing rules go to position 1.
ensure -p tcp --dport 18190 -j DROP
ensure -p tcp -s 172.31.1.233/32 --dport 18190 -j ACCEPT
ensure -i lo -p tcp --dport 18190 -j ACCEPT
ensure -p tcp --dport 3306 -j DROP
ensure -p tcp -s 172.31.0.0/16 --dport 3306 -j ACCEPT
ensure -i lo -p tcp --dport 3306 -j ACCEPT
