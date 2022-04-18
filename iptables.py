from unicodedata import name
import iptc
import list

tables = ["filter", "nat", "mangle", "raw"]
chains = ["POSTROUTING", "INPUT", "OUTPUT", "FORWARD"]

def flush_chain():
    try:
        for table in tables:
            tab = iptc.Table(table)
            for chain in chains:
                ch = iptc.Chain(tab, chain)
                if ch:
                    rules = ch.rules
                    for rule in rules:
                        ch.delete_rule(rule)
                        ch.delete_chain(table, chain, flush=True)
    
    except iptc.ip4tc.IPTCError as error:
        print(error)


def nat():
    # [{"out-interface": "enxb827eb8879e7", "target": "MASQUERADE", "counters": [995, 151619]}, {"out-interface": "enxb827eb8879e7", "target": "MASQUERADE", "counters": [0, 0]}]
    add_nat_chain = iptc.easy.add_chain("nat", "POSTROUTING")
    get_nat_chain = iptc.Chain("nat", "POSTROUTING")
    rule_nat = {
                "out-interface": "enxb827eb8879e7",
                "target": "MASQUERADE"
            }
    get_nat_chain.insert_rule("nat", "POSTROUTING", rule_nat)


def forward():
    # [{"out-interface": "wlan0", "state": {"state": "RELATED,ESTABLISHED"}, "in-interface": "enxb827eb8879e7", "target": "ACCEPT", "counters": [13411, 10584119]}, 
    # {"out-interface": "enxb827eb8879e7", "in-interface": "wlan0", "target": "ACCEPT", "counters": [11969, 2618192]}]
    add_ff_chain = iptc.easy.add_chain("filter", "FORWARD")
    get_ff_chain = iptc.Chain("filter", "FORWARD")
    rule_forward = [{"rule": [
                                {
                                    "out-interface": "enxb827eb8879e7",
                                    "in-interface": "wlan0",
                                    "target": "ACCEPT"
                                },
                                {
                                    "out-interface": "wlan0",
                                    "in-interface": "enxb827eb8879e7",
                                    "target": "ACCEPT",
                                    "state": {"state": "RELATED,ESTABLISHED"}
                                }
                            ]
                        }
                ]
    for rules in rule_forward:
        for rule in rules["rule"]:
            get_ff_chain.insert_rule("filter", "FORWARD", rule)

# disable icmp request for raspi and iot devices
def ssh_rules():
    add_ssh_chain = iptc.easy.add_chain("filter", "SSHATTACK")
    get_ssh_chain = iptc.Chain("filter", "SSHATTACK")
    rule_add_log = [{"rule": [
                                {"target": "DROP"},
                                {"target":
                                    {"LOG": {
                                        "log_prefix": "Possible SSH attack!",
                                        "log_level": "7"
                                        }
                                    }
                                }
                            ]
                        }
                ]
    for rules in rule_add_log:
        for rule in rules["rule"]:
            get_ssh_chain.insert_rule("filter", "SSHATTACK", rule)

    get_fi_chain = iptc.Chain("filter", "INPUT")
    for ip in list.allow_ssh:
        rule_block_login = [{"rule":[
                                        {
                                            "protocol": "tcp", 
                                            "target": "SSHATTACK",
                                            "src": "!%s" % ip, 
                                            "tcp": {"dport": "22"}, 
                                        },
                                        {
                                            "target": "SSHATTACK",
                                            "protocol": "tcp",
                                            "recent": {
                                                        "seconds": "60", # change to 3600 later
                                                        # "update": "",
                                                        "hitcount": "4"
                                                    },
                                            "state": {"state": "NEW"},
                                            "tcp": {"dport": "22"}
                                        },
                                        {
                                            # "recent": {"set": "",},
                                            "state": {"state": "NEW"},
                                            "protocol": "tcp",
                                            "tcp": {"dport": "22"},
                                        }
                                    ]
                                }
                            ]

        for rules in rule_block_login:
            for rule in rules["rule"]:
                get_fi_chain.insert_rule("filter", "INPUT", rule)

#iptables -A INPUT -p icmp -i wlan0 -j DROP
#{"in-interface": "wlan0", "protocol": "icmp", "target": "DROP", "counters": [525, 44194]}]
def block_icmp():
    get_icmp_chain = iptc.Chain("filter", "INPUT")
    rule_block_login = {
                        "protocol": "icmp", 
                        "target": "DROP",
                        "in-interface": "wlan0", 
                    }
    get_icmp_chain.insert_rule("filter", "INPUT", rule_block_login)

if __name__ == "__main__":
    flush_chain()
    nat()
    forward()
    ssh_rules()
    block_icmp()