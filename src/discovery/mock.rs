//! Fixture backend — used on non-Linux machines (`--mock` auto-detected on
//! Windows, or forced with `--mock`). Lets the full UI + plan/apply/rollback
//! pipeline be exercised without a real router.

use serde_json::{json, Value};

pub fn detection() -> Value {
    json!({
        "ts": "2026-10-04 12:00:00",
        "mode": "mock",
        "kernel": "6.12.45-1",
        "backends": {
            "iproute2": {"present": true},
            "network_manager": {"present": true, "running": true, "version": "nmcli tool, version 1.52.0"},
            "networkd": {"present": true, "running": false},
            "ifupdown": {"present": false, "interfaces_file": false},
            "nftables": {"present": true, "running": true, "rules": 27},
            "iptables": {"present": true},
            "dnsmasq": {"present": true, "running": true},
            "kea": {"present": false},
            "isc_dhcp": {"present": false},
            "docker": {"present": true, "version": "27.3.1"},
            "hostapd": {"present": false},
            "pppd": {"present": true}
        },
        "promise": "本次检测为只读：未修改任何网络配置、未安装任何软件包。"
    })
}

pub fn interfaces() -> Value {
    json!({
        "default_devs": ["ppp0"],
        "interfaces": [
            {
                "name": "lo", "ifindex": 1, "kind": "loopback", "category": "loopback",
                "operstate": "UNKNOWN", "up": true, "mac": "00:00:00:00:00:00", "mtu": 65536,
                "flags": [], "parent": null, "vlan_id": null,
                "addr4": ["127.0.0.1/8"], "addr6": ["::1/128"],
                "rx_bytes": 1827364, "tx_bytes": 1827364, "is_default": false, "qdisc": "noqueue", "neighbors": 0
            },
            {
                "name": "eth0", "ifindex": 2, "kind": "ethernet", "category": "ethernet",
                "operstate": "UP", "up": true, "mac": "2c:56:87:a1:30:11", "mtu": 1500,
                "flags": [], "parent": null, "vlan_id": null,
                "addr4": [], "addr6": ["fe80::2e56:87ff:fea1:3011/64"],
                "rx_bytes": 8472912837u64, "tx_bytes": 339201847, "is_default": false, "qdisc": "fq_codel", "neighbors": 2
            },
            {
                "name": "ppp0", "ifindex": 6, "kind": "ppp", "category": "ppp",
                "operstate": "UNKNOWN", "up": true, "mac": "", "mtu": 1492,
                "flags": ["POINTOPOINT", "NOARP"], "parent": "eth0", "vlan_id": null,
                "addr4": ["100.64.18.23/32"], "addr6": [],
                "rx_bytes": 5172839201u64, "tx_bytes": 912743820, "is_default": true, "qdisc": "noqueue", "neighbors": 0
            },
            {
                "name": "eth1", "ifindex": 3, "kind": "ethernet", "category": "ethernet",
                "operstate": "UP", "up": true, "mac": "2c:56:87:a1:30:12", "mtu": 1500,
                "flags": [], "parent": null, "vlan_id": null,
                "addr4": ["192.168.50.2/24"], "addr6": [],
                "rx_bytes": 1294827361u64, "tx_bytes": 384716291, "is_default": false, "qdisc": "fq_codel", "neighbors": 3
            },
            {
                "name": "br-lan", "ifindex": 7, "kind": "bridge", "category": "bridge",
                "operstate": "UP", "up": true, "mac": "2c:56:87:a1:30:20", "mtu": 1500,
                "flags": [], "parent": null, "vlan_id": null,
                "addr4": ["192.168.1.1/24"], "addr6": ["fd00::1/64"],
                "rx_bytes": 3918274612u64, "tx_bytes": 4291827364u64, "is_default": false, "qdisc": "fq_codel", "neighbors": 14
            },
            {
                "name": "enp2s0", "ifindex": 4, "kind": "ethernet", "category": "ethernet",
                "operstate": "UP", "up": true, "mac": "2c:56:87:a1:30:21", "mtu": 1500,
                "flags": [], "parent": "br-lan", "vlan_id": null,
                "addr4": [], "addr6": [],
                "rx_bytes": 3910273641u64, "tx_bytes": 4283726192u64, "is_default": false, "qdisc": "noqueue", "neighbors": 9
            },
            {
                "name": "enp3s0", "ifindex": 5, "kind": "ethernet", "category": "ethernet",
                "operstate": "DOWN", "up": false, "mac": "2c:56:87:a1:30:22", "mtu": 1500,
                "flags": [], "parent": "br-lan", "vlan_id": null,
                "addr4": [], "addr6": [],
                "rx_bytes": 0, "tx_bytes": 0, "is_default": false, "qdisc": "noqueue", "neighbors": 0
            },
            {
                "name": "vlan10", "ifindex": 8, "kind": "vlan", "category": "vlan",
                "operstate": "UP", "up": true, "mac": "2c:56:87:a1:30:20", "mtu": 1500,
                "flags": [], "parent": "br-lan", "vlan_id": 10,
                "addr4": ["192.168.10.1/24"], "addr6": [],
                "rx_bytes": 284716291, "tx_bytes": 192837465, "is_default": false, "qdisc": "fq_codel", "neighbors": 4
            },
            {
                "name": "vlan20", "ifindex": 9, "kind": "vlan", "category": "vlan",
                "operstate": "UP", "up": true, "mac": "2c:56:87:a1:30:20", "mtu": 1500,
                "flags": [], "parent": "br-lan", "vlan_id": 20,
                "addr4": ["192.168.20.1/24"], "addr6": [],
                "rx_bytes": 91827364, "tx_bytes": 63728192, "is_default": false, "qdisc": "fq_codel", "neighbors": 7
            },
            {
                "name": "wg0", "ifindex": 10, "kind": "wireguard", "category": "vpn",
                "operstate": "UNKNOWN", "up": true, "mac": "", "mtu": 1420,
                "flags": [], "parent": null, "vlan_id": null,
                "addr4": ["10.66.66.1/24"], "addr6": [],
                "rx_bytes": 73829174, "tx_bytes": 62918273, "is_default": false, "qdisc": "noqueue", "neighbors": 1
            }
        ]
    })
}

pub fn routes() -> Value {
    json!({
        "default_gw": "100.64.18.23",
        "default_dev": "ppp0",
        "routes": [
            {"dst": "default", "gateway": "100.64.18.23", "dev": "ppp0", "prefsrc": "", "table": "main", "protocol": "ppp", "scope": "global", "metric": 100, "type": "", "src": ""},
            {"dst": "default", "gateway": "192.168.50.1", "dev": "eth1", "prefsrc": "", "table": "main", "protocol": "dhcp", "scope": "global", "metric": 600, "type": "", "src": ""},
            {"dst": "default", "gateway": "192.168.50.1", "dev": "eth1", "prefsrc": "", "table": "100", "protocol": "dhcp", "scope": "global", "metric": 600, "type": "", "src": ""},
            {"dst": "192.168.50.0/24", "gateway": "", "dev": "eth1", "prefsrc": "192.168.50.2", "table": "main", "protocol": "kernel", "scope": "link", "metric": 100, "type": "unicast", "src": ""},
            {"dst": "192.168.1.0/24", "gateway": "", "dev": "br-lan", "prefsrc": "192.168.1.1", "table": "main", "protocol": "kernel", "scope": "link", "metric": 100, "type": "unicast", "src": ""},
            {"dst": "192.168.10.0/24", "gateway": "", "dev": "vlan10", "prefsrc": "192.168.10.1", "table": "main", "protocol": "kernel", "scope": "link", "metric": 100, "type": "unicast", "src": ""},
            {"dst": "192.168.20.0/24", "gateway": "", "dev": "vlan20", "prefsrc": "192.168.20.1", "table": "main", "protocol": "kernel", "scope": "link", "metric": 100, "type": "unicast", "src": ""},
            {"dst": "10.66.66.0/24", "gateway": "", "dev": "wg0", "prefsrc": "10.66.66.1", "table": "main", "protocol": "kernel", "scope": "link", "metric": 0, "type": "unicast", "src": ""},
            {"dst": "10.0.0.0/8 via 192.168.1.254", "gateway": "192.168.1.254", "dev": "br-lan", "prefsrc": "", "table": "main", "protocol": "static", "scope": "universe", "metric": 100, "type": "unicast", "src": ""},
            {"dst": "172.16.0.0/12", "gateway": "192.168.1.254", "dev": "br-lan", "prefsrc": "", "table": "200", "protocol": "static", "scope": "universe", "metric": 50, "type": "unicast", "src": ""}
        ],
        "rules": [
            {"priority": 0, "table": "local", "action": "lookup", "src": ""},
            {"priority": 32766, "table": "main", "action": "lookup", "src": ""},
            {"priority": 32767, "table": "default", "action": "lookup", "src": ""},
            {"priority": 100, "table": "100", "action": "lookup", "src": "192.168.1.0/24"}
        ]
    })
}

pub fn nm_devices() -> Vec<Value> {
    vec![
        json!({"device": "lo", "type": "loopback", "state": "unmanaged", "connection": "--"}),
        json!({"device": "eth0", "type": "ethernet", "state": "connected", "connection": "WAN1-PPPoE"}),
        json!({"device": "ppp0", "type": "ppp", "state": "connected", "connection": "WAN1-PPPoE"}),
        json!({"device": "eth1", "type": "ethernet", "state": "connected", "connection": "WAN2-DHCP"}),
        json!({"device": "br-lan", "type": "bridge", "state": "connected", "connection": "LAN"}),
        json!({"device": "enp2s0", "type": "ethernet", "state": "connected", "connection": "--"}),
        json!({"device": "enp3s0", "type": "ethernet", "state": "disconnected", "connection": "--"}),
        json!({"device": "vlan10", "type": "vlan", "state": "connected", "connection": "VLAN10-Guest"}),
        json!({"device": "vlan20", "type": "vlan", "state": "connected", "connection": "VLAN20-IoT"}),
        json!({"device": "wg0", "type": "wireguard", "state": "connected", "connection": "WG-Home"}),
    ]
}

pub fn nm_connections() -> Vec<Value> {
    vec![
        json!({"name": "WAN1-PPPoE", "uuid": "a1b2c3d4-1111-4a4a-9a9a-000000000001", "type": "pppoe", "device": "ppp0"}),
        json!({"name": "WAN2-DHCP", "uuid": "a1b2c3d4-2222-4a4a-9a9a-000000000002", "type": "802-3-ethernet", "device": "eth1"}),
        json!({"name": "LAN", "uuid": "a1b2c3d4-3333-4a4a-9a9a-000000000003", "type": "bridge", "device": "br-lan"}),
        json!({"name": "VLAN10-Guest", "uuid": "a1b2c3d4-4444-4a4a-9a9a-000000000004", "type": "vlan", "device": "vlan10"}),
        json!({"name": "VLAN20-IoT", "uuid": "a1b2c3d4-5555-4a4a-9a9a-000000000005", "type": "vlan", "device": "vlan20"}),
        json!({"name": "WG-Home", "uuid": "a1b2c3d4-6666-4a4a-9a9a-000000000006", "type": "wireguard", "device": "wg0"}),
        json!({"name": "enp2s0-bind", "uuid": "a1b2c3d4-7777-4a4a-9a9a-000000000007", "type": "802-3-ethernet", "device": ""}),
    ]
}

pub fn nm_connection_detail(conn_ref: &str) -> Value {
    let (method, addrs, gw, dns) = if conn_ref.contains("WAN2") || conn_ref.contains("2222") {
        ("auto", "192.168.50.2/24", "192.168.50.1", "223.5.5.5,119.29.29.29")
    } else if conn_ref.contains("VLAN10") || conn_ref.contains("4444") {
        ("manual", "192.168.10.1/24", "", "223.5.5.5")
    } else if conn_ref.contains("VLAN20") || conn_ref.contains("5555") {
        ("manual", "192.168.20.1/24", "", "223.5.5.5")
    } else if conn_ref.contains("LAN") || conn_ref.contains("3333") {
        ("manual", "192.168.1.1/24", "", "127.0.0.1")
    } else if conn_ref.contains("WAN1") || conn_ref.contains("1111") {
        ("pppoe", "", "", "223.5.5.5")
    } else {
        ("auto", "", "", "")
    };
    let is_pppoe = conn_ref.contains("WAN1") || conn_ref.contains("1111");
    json!({
        "keys": {
            "connection.id": if conn_ref.contains("WAN2") { "WAN2-DHCP" } else if is_pppoe { "WAN1-PPPoE" } else { "LAN" },
            "connection.uuid": conn_ref,
            "connection.type": if is_pppoe { "pppoe" } else { "802-3-ethernet" },
            "connection.interface-name": if conn_ref.contains("WAN2") { "eth1" } else if is_pppoe { "enp1s0" } else { "br-lan" },
            "connection.autoconnect": "yes",
            "connection.autoconnect-priority": "0",
            "ipv4.method": method,
            "ipv4.addresses": addrs,
            "ipv4.gateway": gw,
            "ipv4.dns": dns,
            "ipv4.never-default": if conn_ref.contains("WAN2") { "no" } else { "no" },
            "ipv4.route-metric": if conn_ref.contains("WAN2") { "200" } else { "100" },
            "ipv4.route-table": "auto",
            "ipv6.method": "disabled",
            "ipv6.addresses": "",
            "802-3.ethernet.mtu": "1500",
            "ppp.mtu": if is_pppoe { "1492" } else { "" },
            "pppoe.username": if is_pppoe { "user@isp.example" } else { "" },
            "pppoe.service": if is_pppoe { "" } else { "" }
        }
    })
}

pub fn nat() -> Value {
    json!({
        "backend": "nft",
        "nft": {
            "present": true,
            "ruleset_text":
"# Table inet filter\n\
table inet filter {\n\
\tchain input {\n\
\t\ttype filter hook input priority filter; policy accept;\n\
\t\tct state established,related accept\n\
\t\tiif \"lo\" accept\n\
\t\tct state invalid drop\n\
\t\ttcp dport { 22, 53, 67, 8080 } accept comment \"lan services\"\n\
\t\tiifname != \"br-lan\" udp dport 67 drop\n\
\t}\n\
\tchain forward {\n\
\t\ttype filter hook forward priority filter; policy drop;\n\
\t\tct state established,related accept\n\
\t\tct state invalid drop\n\
\t\tiifname \"br-lan\" oifname { \"ppp0\", \"eth1\" } accept comment \"lan to wan\"\n\
\t\tiifname \"ppp0\" ct state established accept\n\
\t}\n\
}\n\
# Table ip nat\n\
table ip nat {\n\
\tchain prerouting {\n\
\t\ttype nat hook prerouting priority dstnat; policy accept;\n\
\t}\n\
\tchain postrouting {\n\
\t\ttype nat hook postrouting priority srcnat; policy accept;\n\
\t\toifname { \"ppp0\", \"eth1\" } masquerade\n\
\t}\n\
}\n\
# Table inet routedeck (managed by RouteDeck)\n\
table inet routedeck {\n\
\tchain prerouting {\n\
\t\ttype nat hook prerouting priority dstnat; policy accept;\n\
\t\tiifname \"ppp0\" tcp dport 8080 dnat to 192.168.1.10:80 comment \"rd:fwd01 | 8080/tcp → 192.168.1.10:80 (WAN1)\"\n\
\t\tiifname \"ppp0\" tcp dport 51820 dnat to 192.168.1.1:51820 comment \"rd:fwd02 | 51820/udp → 192.168.1.1:51820 (WAN1)\"\n\
\t}\n\
\tchain postrouting {\n\
\t\ttype nat hook postrouting priority srcnat; policy accept;\n\
\t\toifname \"eth1\" masquerade comment \"rd:masq-eth1 | masquerade eth1\"\n\
\t}\n\
}",
            "tables": [
                {"family": "inet", "name": "filter", "rule_total": 9, "chains": [
                    {"name": "input", "type": "filter", "hook": "input", "priority": 0, "policy": "accept", "rule_total": 6},
                    {"name": "forward", "type": "filter", "hook": "forward", "priority": 0, "policy": "drop", "rule_total": 4}
                ]},
                {"family": "ip", "name": "nat", "rule_total": 2, "chains": [
                    {"name": "prerouting", "type": "nat", "hook": "prerouting", "priority": -100, "policy": "accept", "rule_total": 0},
                    {"name": "postrouting", "type": "nat", "hook": "postrouting", "priority": 100, "policy": "accept", "rule_total": 1}
                ]},
                {"family": "inet", "name": "routedeck", "rule_total": 3, "chains": [
                    {"name": "prerouting", "type": "nat", "hook": "prerouting", "priority": -100, "policy": "accept", "rule_total": 2},
                    {"name": "postrouting", "type": "nat", "hook": "postrouting", "priority": 100, "policy": "accept", "rule_total": 1}
                ]}
            ],
            "managed": {
                "available": true,
                "table_exists": true,
                "table": "inet routedeck",
                "rules": [
                    {"handle": 7, "chain": "prerouting", "id": "fwd01", "comment": "rd:fwd01 | 8080/tcp → 192.168.1.10:80 (WAN1)", "desc": "8080/tcp → 192.168.1.10:80 (WAN1)"},
                    {"handle": 9, "chain": "prerouting", "id": "fwd02", "comment": "rd:fwd02 | 51820/udp → 192.168.1.1:51820 (WAN1)", "desc": "51820/udp → 192.168.1.1:51820 (WAN1)"},
                    {"handle": 14, "chain": "postrouting", "id": "masq-eth1", "comment": "rd:masq-eth1 | masquerade eth1", "desc": "masquerade eth1"}
                ]
            }
        },
        "iptables": {"present": true},
        "summary": {
            "masquerade": true,
            "masquerade_ifaces": ["ppp0", "eth1"],
            "forward_policy": "drop",
            "dnat_count": 2
        }
    })
}

pub fn dhcp() -> Value {
    json!({
        "backend": "dnsmasq",
        "dnsmasq": {
            "present": true,
            "running": true,
            "conf_files": ["/etc/dnsmasq.conf", "/etc/dnsmasq.d/routedeck.conf"],
            "conf_dir_included": "/etc/dnsmasq.d/,*.conf",
            "our_snippet": {
                "path": "/etc/dnsmasq.d/routedeck.conf",
                "exists": true,
                "ours": true,
                "bindings": [
                    {"mac": "9c:b6:d8:11:2a:30", "ip": "192.168.1.10", "name": "nas"},
                    {"mac": "00:1e:42:aa:bb:cc", "ip": "192.168.1.20", "name": "ap-floor1"}
                ],
                "upstreams": ["223.5.5.5", "119.29.29.29"],
                "scope": {"start": "192.168.1.100", "end": "192.168.1.240", "netmask": "255.255.255.0", "lease": "12h"},
                "options": {"gateway": "192.168.1.1", "dns": ["223.5.5.5", "119.29.29.29"], "domain": "lan"},
                "hosts": [
                    {"name": "nas.lan", "ip": "192.168.1.10"},
                    {"name": "cam-front.lan", "ip": "192.168.20.31"}
                ],
                "content": "# Managed by RouteDeck — do not edit by hand (regenerated from UI state)\nserver=223.5.5.5\nserver=119.29.29.29\ndhcp-range=192.168.1.100,192.168.1.240,255.255.255.0,12h\ndhcp-option=3,192.168.1.1\ndhcp-option=6,223.5.5.5,119.29.29.29\ndhcp-option=15,lan\ndhcp-host=9c:b6:d8:11:2a:30,192.168.1.10,nas\ndhcp-host=00:1e:42:aa:bb:cc,192.168.1.20,ap-floor1\naddress=/nas.lan/192.168.1.10\naddress=/cam-front.lan/192.168.20.31\n"
            },
            "upstreams": ["223.5.5.5", "119.29.29.29"],
            "foreign_ranges": [
                {"file": "/etc/dnsmasq.conf", "line": "dhcp-range=192.168.2.50,192.168.2.150,12h"}
            ],
            "leases": [
                {"mac": "9c:b6:d8:11:2a:30", "ip": "192.168.1.10", "name": "nas", "expires_ts": 1790000000u64, "remaining_secs": 86400, "lease_id": "1", "src": "/var/lib/misc/dnsmasq.leases"},
                {"mac": "3c:22:fb:88:11:02", "ip": "192.168.1.33", "name": "iphone-x", "expires_ts": 1790000000u64, "remaining_secs": 36000, "lease_id": "2", "src": "/var/lib/misc/dnsmasq.leases"},
                {"mac": "b8:27:eb:44:12:9f", "ip": "192.168.1.44", "name": "pi-hole", "expires_ts": 1790000000u64, "remaining_secs": 61200, "lease_id": "3", "src": "/var/lib/misc/dnsmasq.leases"},
                {"mac": "f0:9f:c2:11:7d:21", "ip": "192.168.10.12", "name": "guest-laptop", "expires_ts": 1790000000u64, "remaining_secs": 7200, "lease_id": "4", "src": "/var/lib/misc/dnsmasq.leases"},
                {"mac": "44:65:0d:ee:31:01", "ip": "192.168.20.31", "name": "cam-front", "expires_ts": 1790000000u64, "remaining_secs": 54000, "lease_id": "5", "src": "/var/lib/misc/dnsmasq.leases"},
                {"mac": "50:c7:bf:09:55:aa", "ip": "192.168.20.32", "name": "esp32-sensor", "expires_ts": 1790000000u64, "remaining_secs": 43000, "lease_id": "6", "src": "/var/lib/misc/dnsmasq.leases"}
            ],
            "lease_count": 6
        },
        "nm_ics": [],
        "kea": {"present": false},
        "isc": {"present": false},
        "dns": {
            "resolv_nameservers": ["127.0.0.1"],
            "resolv_path": "/etc/resolv.conf",
            "resolv_target": "/run/dnsmasq/resolv.conf",
            "resolv_is_stub": true,
            "dnsmasq_upstreams": ["223.5.5.5", "119.29.29.29"],
            "source": "dnsmasq",
            "nm_dns": []
        }
    })
}

pub fn services() -> Value {
    json!({
        "listening": [
            {"proto": "tcp", "state": "LISTEN", "local": "0.0.0.0:22", "peer": "0.0.0.0:*", "process": "sshd", "pid": 812},
            {"proto": "tcp", "state": "LISTEN", "local": "0.0.0.0:53", "peer": "0.0.0.0:*", "process": "dnsmasq", "pid": 945},
            {"proto": "tcp", "state": "LISTEN", "local": "0.0.0.0:8080", "peer": "0.0.0.0:*", "process": "node", "pid": 1271},
            {"proto": "tcp", "state": "LISTEN", "local": "0.0.0.0:8443", "peer": "0.0.0.0:*", "process": "nginx", "pid": 1103},
            {"proto": "tcp", "state": "LISTEN", "local": "127.0.0.1:3000", "peer": "0.0.0.0:*", "process": "grafana", "pid": 1310},
            {"proto": "tcp", "state": "LISTEN", "local": "0.0.0.0:5000", "peer": "0.0.0.0:*", "process": "python3", "pid": 1488},
            {"proto": "tcp", "state": "LISTEN", "local": "0.0.0.0:9090", "peer": "0.0.0.0:*", "process": "prometheus", "pid": 1502},
            {"proto": "tcp", "state": "LISTEN", "local": "0.0.0.0:16666", "peer": "0.0.0.0:*", "process": "openclash", "pid": 1677},
            {"proto": "tcp", "state": "LISTEN", "local": "0.0.0.0:5700", "peer": "0.0.0.0:*", "process": "qinglong", "pid": 1705},
            {"proto": "udp", "state": "UNCONN", "local": "0.0.0.0:67", "peer": "0.0.0.0:*", "process": "dnsmasq", "pid": 945},
            {"proto": "udp", "state": "UNCONN", "local": "0.0.0.0:51820", "peer": "0.0.0.0:*", "process": "wg-quick", "pid": 701}
        ],
        "web_listeners": [
            {"proto": "tcp", "state": "LISTEN", "local": "0.0.0.0:8080", "peer": "0.0.0.0:*", "process": "node", "pid": 1271},
            {"proto": "tcp", "state": "LISTEN", "local": "0.0.0.0:8443", "peer": "0.0.0.0:*", "process": "nginx", "pid": 1103},
            {"proto": "tcp", "state": "LISTEN", "local": "127.0.0.1:3000", "peer": "0.0.0.0:*", "process": "grafana", "pid": 1310},
            {"proto": "tcp", "state": "LISTEN", "local": "0.0.0.0:5000", "peer": "0.0.0.0:*", "process": "python3", "pid": 1488},
            {"proto": "tcp", "state": "LISTEN", "local": "0.0.0.0:9090", "peer": "0.0.0.0:*", "process": "prometheus", "pid": 1502},
            {"proto": "tcp", "state": "LISTEN", "local": "0.0.0.0:16666", "peer": "0.0.0.0:*", "process": "openclash", "pid": 1677},
            {"proto": "tcp", "state": "LISTEN", "local": "0.0.0.0:5700", "peer": "0.0.0.0:*", "process": "qinglong", "pid": 1705}
        ],
        "key_units": [
            {"name": "NetworkManager", "state": "active"},
            {"name": "systemd-networkd", "state": "inactive"},
            {"name": "dnsmasq", "state": "active"},
            {"name": "nftables", "state": "active"},
            {"name": "docker", "state": "active"},
            {"name": "ssh", "state": "active"},
            {"name": "hostapd", "state": "inactive"},
            {"name": "systemd-resolved", "state": "inactive"}
        ],
        "running": [
            {"unit": "NetworkManager.service", "load": "loaded", "active": "active", "sub": "running", "desc": "Network Manager"},
            {"unit": "docker.service", "load": "loaded", "active": "active", "sub": "running", "desc": "Docker Application Container Engine"},
            {"unit": "dnsmasq.service", "load": "loaded", "active": "active", "sub": "running", "desc": "dnsmasq - DHCP and DNS server"},
            {"unit": "nftables.service", "load": "loaded", "active": "active", "sub": "exited", "desc": "nftables"},
            {"unit": "ssh.service", "load": "loaded", "active": "active", "sub": "running", "desc": "OpenBSD Secure Shell server"},
            {"unit": "nginx.service", "load": "loaded", "active": "active", "sub": "running", "desc": "A high performance web server"},
            {"unit": "routedeck.service", "load": "loaded", "active": "active", "sub": "running", "desc": "RouteDeck router panel"}
        ],
        "running_count": 7
    })
}

pub fn tasks() -> Value {
    json!({
        "tasks": [
            {"name": "daily-reboot", "kind": "reboot", "on_calendar": "*-*-* 03:30:00", "exec": "/usr/sbin/reboot", "unit": "routedeck-task-daily-reboot.timer", "enabled": "enabled", "active": "active", "next": "Tomorrow 03:30:00"},
            {"name": "weekly-logclean", "kind": "command", "on_calendar": "Mon *-*-* 04:00:00", "exec": "/usr/bin/journalctl --vacuum-time=14d", "unit": "routedeck-task-weekly-logclean.timer", "enabled": "enabled", "active": "inactive", "next": "Mon 04:00:00"}
        ],
        "unit_dir": "/etc/systemd/system"
    })
}

pub fn docker() -> Value {
    json!({
        "present": true,
        "version": "27.3.1",
        "running": 4,
        "containers": [
            {"id": "a1b2c3d4e5f6", "names": "qinglong", "image": "whyour/qinglong:latest", "state": "running", "status": "Up 12 days", "ports": "0.0.0.0:5700->5700/tcp", "created": "2026-09-22 10:00:00", "labels": "com.docker.compose.project=ops,com.docker.compose.project.working_dir=/opt/ops", "project": "ops"},
            {"id": "b2c3d4e5f6a1", "names": "openclash", "image": "vernesoft/openclash:latest", "state": "running", "status": "Up 12 days", "ports": "0.0.0.0:16666->16666/tcp", "created": "2026-09-22 10:00:05", "labels": "com.docker.compose.project=ops,com.docker.compose.project.working_dir=/opt/ops", "project": "ops"},
            {"id": "c3d4e5f6a1b2", "names": "frpc", "image": "snowdreamtech/frpc:latest", "state": "running", "status": "Up 12 days", "ports": "", "created": "2026-09-22 10:00:09", "labels": "com.docker.compose.project=ops,com.docker.compose.project.working_dir=/opt/ops", "project": "ops"},
            {"id": "d4e5f6a1b2c3", "names": "uptime-kuma", "names2": "", "image": "louislam/uptime-kuma:1", "state": "running", "status": "Up 5 days", "ports": "0.0.0.0:3001->3001/tcp", "created": "2026-09-29 08:12:44", "labels": "com.docker.compose.project=monitor,com.docker.compose.project.working_dir=/opt/monitor", "project": "monitor"},
            {"id": "e5f6a1b2c3d4", "names": "old-panel", "image": "nginx:alpine", "state": "exited", "status": "Exited (0) 3 days ago", "ports": "", "created": "2026-08-01 11:00:00", "labels": "", "project": ""}
        ],
        "images": [
            {"id": "sha256:1a2b3c", "repository": "whyour/qinglong", "tag": "latest", "size": "250MB", "created": "2 weeks ago"},
            {"id": "sha256:2b3c4d", "repository": "vernesoft/openclash", "tag": "latest", "size": "180MB", "created": "1 month ago"},
            {"id": "sha256:3c4d5e", "repository": "louislam/uptime-kuma", "tag": "1", "size": "95MB", "created": "3 weeks ago"},
            {"id": "sha256:4d5e6f", "repository": "nginx", "tag": "alpine", "size": "52MB", "created": "2 months ago"}
        ],
        "projects": [
            {"name": "ops", "workdir": "/opt/ops", "count": 3, "running": 3},
            {"name": "monitor", "workdir": "/opt/monitor", "count": 1, "running": 1}
        ]
    })
}

pub fn packages() -> Value {
    let rows = [
        ("network-manager", "1.52.0-3"),
        ("nftables", "1.2.9-1"),
        ("dnsmasq", "2.91-3"),
        ("iproute2", "6.12.1-1"),
        ("ppp", "2.5.1-3"),
        ("iptables", "1.8.11-4"),
        ("openssh-server", "1:9.9p1-6"),
        ("nginx", "1.26.3-1"),
        ("docker.io", "27.3.1+dfsg.2-3"),
        ("docker-compose-v2", "2.29.7-1"),
        ("python3", "3.13.5-1"),
        ("nodejs", "22.14.0+dfsg-1"),
        ("prometheus-node-exporter", "1.8.2-2"),
        ("wireguard-tools", "1.0.20210914-1"),
        ("bash", "5.2.37-1"),
        ("vim-tiny", "9.1.0700-3"),
        ("sudo", "1.9.17-1"),
        ("curl", "8.14.1-1"),
        ("git", "1:2.47.2-1"),
        ("rsync", "3.4.0-1"),
        ("htop", "3.4.0-1"),
        ("qemu-guest-agent", "1:9.2.4+ds-1"),
        ("pihole-FTL", "5.25.2"),
        ("grafana", "11.4.0"),
        ("tailscale", "1.76.6"),
    ];
    let items: Vec<Value> = rows
        .iter()
        .map(|(n, v)| json!({"name": n, "version": v}))
        .collect();
    json!({"total": items.len(), "items": items})
}
