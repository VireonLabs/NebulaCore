#!/bin/bash
set -e

AGENT_USER="${AGENT_USER:-$(whoami)}"
AGENT_BINARY="${AGENT_BINARY:-/usr/local/bin/agent}"
AGENT_PORT="${AGENT_PORT:-9000}"
AGENT_GROUP="kvm"
DHCP_CLIENT="${DHCP_CLIENT:-dhclient}"
NET_COUNT="${NET_COUNT:-2}"
TAP_PREFIX="${TAP_PREFIX:-tap}"
BRIDGE_PREFIX="${BRIDGE_PREFIX:-br}"
NS_PREFIX="${NS_PREFIX:-agentns}"
IP_RANGE="${IP_RANGE:-192.168.100}"
IPV6_ENABLED="${IPV6_ENABLED:-1}"
DHCP_RETRIES="${DHCP_RETRIES:-3}"
LOGFILE="/var/log/agent_bootstrap.log"

exec > >(tee -a "$LOGFILE") 2>&1

echo "=== [BOOTSTRAP] $(date) ==="
echo "USER: $AGENT_USER, BINARY: $AGENT_BINARY, NETS: $NET_COUNT, IPV6: $IPV6_ENABLED"

if [[ "$1" == "--cleanup" ]]; then
    echo "[CLEANUP] $(date)"
    for ((i=0; i<NET_COUNT; i++)); do
        TAP_NAME="${TAP_PREFIX}${i}"
        BRIDGE_NAME="${BRIDGE_PREFIX}${i}"
        NS_NAME="${NS_PREFIX}${i}"
        ip link delete $TAP_NAME || true
        ip link delete $BRIDGE_NAME type bridge || true
        ip netns del $NS_NAME || true
        iptables -D INPUT -i $BRIDGE_NAME -p tcp --dport $AGENT_PORT -j ACCEPT || true
        iptables -D INPUT -i $BRIDGE_NAME -j DROP || true
        iptables -D FORWARD -i $BRIDGE_NAME -j ACCEPT || true
        iptables -t nat -D POSTROUTING -o $BRIDGE_NAME -j MASQUERADE || true
        ip6tables -D INPUT -i $BRIDGE_NAME -p tcp --dport $AGENT_PORT -j ACCEPT || true
        ip6tables -D INPUT -i $BRIDGE_NAME -j DROP || true
        ip6tables -D FORWARD -i $BRIDGE_NAME -j ACCEPT || true
    done
    echo "[CLEANUP] Done."
    exit 0
fi

if [[ $EUID -ne 0 ]]; then
    echo "يرجى تشغيل السكربت بصلاحيات root."
    exit 1
fi

if [[ ! -e /dev/kvm ]]; then
    modprobe kvm || modprobe kvm_amd || modprobe kvm_intel || { echo "فشل تحميل kvm"; exit 2; }
fi
if ! grep -q "$AGENT_GROUP" /etc/group; then groupadd $AGENT_GROUP; fi
usermod -aG $AGENT_GROUP $AGENT_USER
chown root:$AGENT_GROUP /dev/kvm
chmod 660 /dev/kvm

apt-get update
apt-get install -y libcap2-bin iproute2 bridge-utils net-tools iptables iptables-persistent
setcap cap_net_admin+ep $AGENT_BINARY

for ((i=0; i<NET_COUNT; i++)); do
    (
        TAP_NAME="${TAP_PREFIX}${i}"
        BRIDGE_NAME="${BRIDGE_PREFIX}${i}"
        NS_NAME="${NS_PREFIX}${i}"
        IPV6_ADDR="fc00::${i}1/64"

        ip link delete $TAP_NAME || true
        ip link delete $BRIDGE_NAME type bridge || true
        ip netns del $NS_NAME || true

        ip netns add $NS_NAME || exit 3
        ip link add $BRIDGE_NAME type bridge || exit 3
        ip link set $BRIDGE_NAME netns $NS_NAME || exit 3
        ip netns exec $NS_NAME ip link set $BRIDGE_NAME up || exit 3
        ip tuntap add $TAP_NAME mode tap user $AGENT_USER || exit 3
        ip link set $TAP_NAME netns $NS_NAME || exit 3
        ip netns exec $NS_NAME ip link set $TAP_NAME up || exit 3
        ip netns exec $NS_NAME ip link set $TAP_NAME master $BRIDGE_NAME || exit 3

        DHCP_OK=0
        if ip netns exec $NS_NAME command -v $DHCP_CLIENT &>/dev/null; then
            for ((try=1; try<=DHCP_RETRIES; try++)); do
                ip netns exec $NS_NAME $DHCP_CLIENT $BRIDGE_NAME && DHCP_OK=1 && break
                sleep 2
            done
        fi
        if [[ $DHCP_OK -eq 0 ]]; then
            ip netns exec $NS_NAME ip addr add "${IP_RANGE}.$((i+10))/24" dev $BRIDGE_NAME
        fi

        if [[ "$IPV6_ENABLED" -eq 1 ]]; then
            ip netns exec $NS_NAME sysctl -w net.ipv6.conf.$BRIDGE_NAME.disable_ipv6=0
            ip netns exec $NS_NAME ip -6 addr add $IPV6_ADDR dev $BRIDGE_NAME
            ip netns exec $NS_NAME ip -6 link set $BRIDGE_NAME up
        fi

        ip netns exec $NS_NAME iptables -A INPUT -i $BRIDGE_NAME -p tcp --dport $AGENT_PORT -j ACCEPT
        ip netns exec $NS_NAME iptables -A INPUT -i $BRIDGE_NAME -j DROP
        ip netns exec $NS_NAME iptables -A FORWARD -i $BRIDGE_NAME -j ACCEPT
        ip netns exec $NS_NAME iptables -t nat -A POSTROUTING -o $BRIDGE_NAME -j MASQUERADE
        if [[ "$IPV6_ENABLED" -eq 1 ]]; then
            ip netns exec $NS_NAME ip6tables -A INPUT -i $BRIDGE_NAME -p tcp --dport $AGENT_PORT -j ACCEPT
            ip netns exec $NS_NAME ip6tables -A INPUT -i $BRIDGE_NAME -j DROP
            ip netns exec $NS_NAME ip6tables -A FORWARD -i $BRIDGE_NAME -j ACCEPT
        fi

        ip netns exec $NS_NAME ip addr show $BRIDGE_NAME
        ip netns exec $NS_NAME ip addr show $TAP_NAME
        ip netns exec $NS_NAME brctl show
        if [[ "$IPV6_ENABLED" -eq 1 ]]; then
            ip netns exec $NS_NAME ip -6 addr show $BRIDGE_NAME
        fi
    ) &
done
wait

sudo -u $AGENT_USER bash -c "test -r /dev/kvm && echo 'OK: يمكن الوصول إلى /dev/kvm' || echo 'خطأ: لا يمكن الوصول إلى /dev/kvm'"
getcap $AGENT_BINARY

if [[ "${AUTO_RUN_AGENT}" == "1" ]]; then
    sudo -u $AGENT_USER $AGENT_BINARY --port $AGENT_PORT
    echo "تم تشغيل الـ agent تلقائيًا."
else
    echo "البيئة جاهزة لتشغيل agent مع Firecracker."
fi

for ((i=0; i<NET_COUNT; i++)); do
    echo "TAP: ${TAP_PREFIX}${i}"
    echo "Bridge: ${BRIDGE_PREFIX}${i}"
    echo "Namespace: ${NS_PREFIX}${i}"
done
echo "Log file: $LOGFILE"