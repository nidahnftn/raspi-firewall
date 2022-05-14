import iptc
import list

tables = ["filter", "mangle", "raw"]
chains = ["POSTROUTING", "INPUT", "OUTPUT", "FORWARD"] 
new_chains = ["SSHATTACK", "PORTATTACK", "UNRECOGDVC", "PINGATTACK"]

def flush_chain():
    try:
        for table in tables:
            tab = iptc.Table(table)
            for chain in chains:
                ch = iptc.Chain(tab, chain)
                if ch:
                   for rule in ch.rules:
                      ch.flush()
                      print("Successfully flush chain: %s." %ch.name)

            for chain in new_chains:
                ch = iptc.Chain(tab, chain)
                if ch:
                   for rule in ch.rules:
                      ch.flush()
                      print("Successfully flush chain: %s." %ch.name)
    
    except iptc.IPTCError as error:
        print(error)

def add_chain():
    for chain in new_chains:
        try:
            iptc.easy.add_chain("filter", chain)

        except iptc.IPTCError as error:
            print(error)

def nat():
    # [{"out-interface": "enxb827eb8879e7", "target": "MASQUERADE", "counters": [995, 151619]}, {"out-interface": "enxb827eb8879e7", "target": "MASQUERADE", "counters": [0, 0]}]
    try:
        rule_nat = {
                    "out-interface": "enxb827eb8879e7",
                    "target": "MASQUERADE"
                }
        iptc.easy.insert_rule("nat", "POSTROUTING", rule_nat)
    
    except iptc.IPTCError as error:
        print(error)


def forward():
    # [{"out-interface": "wlan0", "state": {"state": "RELATED,ESTABLISHED"}, "in-interface": "enxb827eb8879e7", "target": "ACCEPT", "counters": [13411, 10584119]}, 
    # {"out-interface": "enxb827eb8879e7", "in-interface": "wlan0", "target": "ACCEPT", "counters": [11969, 2618192]}]
    try:
        rule_forward = [{"rule": [
                                    {
                                        "out-interface": "enxb827eb8879e7",
                                        "in-interface": "wlan0",
                                        "dst": "192.168.1.100/32",
                                        "target": "ACCEPT"
                                    },
                                    {
                                        "out-interface": "wlan0",
                                        "in-interface": "enxb827eb8879e7",
                                        "src": "192.168.1.100/32",
                                        "target": "ACCEPT",
                                        "state": {"state": "RELATED,ESTABLISHED"}
                                    }
                                ]
                            }
                    ]
        for rules in rule_forward:
            for rule in rules["rule"]:
                iptc.easy.insert_rule("filter", "FORWARD", rule)
                print("Successfully added rule: %s." %rule)
    
    except iptc.IPTCError as error:
        print(error)

#input
#{"set": {"match-set": ["blacklist", "src"]}, "counters": [402, 27609], "target": "CONNECTIONATTEMPT"}
#forward
#[{"set": {"match-set": ["blacklist", "src"]}, "counters": [689, 53663], "target": "CONNECTIONATTEMPT"}, {"set": {"match-set": ["blacklist", "src"]}, "counters": [252, 34577], "target": "DROP"}

def connection_attempt():
    try:
        rule_add_log = [{"rule": [
                                    {"target": "DROP"},
                                    {"target":
                                        {"LOG": {
                                            "log_prefix": "Connection attempt is detected!",
                                            "log_level": "7"
                                            }
                                        }
                                    }
                                ]
                            }
                    ]
        for rules in rule_add_log:
            for rule in rules["rule"]:
                iptc.easy.insert_rule("filter", "UNRECOGDVC", rule)
                print("Successfully added rule: %s." %rule)

        #{"counters": [0, 0], "set": {"match-set": ["blacklist", "src"]}, "target": "CONNECTIONATTEMPT"}
        for ip in list.BLACKLIST_ADDRESS:
            rule_block_connection = {
                                        "target": "UNRECOGDVC",
                                        "src": ip,
                                    }
            for rule in rule_block_connection:
                iptc.easy.insert_rule("filter", "INPUT", rule)
                print("Successfully added rule: %s." %rule)

    except iptc.IPTCError as error:
        print(error)

def ssh_rules():
    try:
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
                iptc.easy.insert_rule("filter", "SSHATTACK", rule)
                print("Successfully added rule: %s." %rule)

        for ip in list.ALLOWED_SSH:
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
                                                            "update": "",
                                                            "hitcount": "4"
                                                        },
                                                "state": {"state": "NEW"},
                                                "tcp": {"dport": "22"}
                                            },
                                            {
                                                "recent": {"set": "",},
                                                "state": {"state": "NEW"},
                                                "protocol": "tcp",
                                                "tcp": {"dport": "22"},
                                            }
                                        ]
                                    }
                                ]

            for rules in rule_block_login:
                for rule in rules["rule"]:
                    iptc.easy.insert_rule("filter", "INPUT", rule)
                    print("Successfully added rule: %s." %rule)
    
    except iptc.IPTCError as error:
        print(error)

#iptables -A INPUT -p icmp -i wlan0 -j DROP
#{"in-interface": "wlan0", "protocol": "icmp", "target": "DROP", "counters": [525, 44194]}]
#{"target": "DROP", "counters": [262, 22008], "protocol": "icmp", "icmp": {"icmp-type": "8"}}]
def block_icmp():
    #{"icmp": {"icmp-type": "8"}, "counters": [0, 0], "dst": "192.168.1.100/32", "target": "DROP", "protocol": "icmp"}
    try:
        rule_add_log = [{"rule": [
                                    {"target": "DROP"},
                                    {"target":
                                        {"LOG": {
                                            "log_prefix": "PING attempt is detected!",
                                            "log_level": "7"
                                            }
                                        }
                                    }
                                ]
                            }
                    ]
        for rules in rule_add_log:
            for rule in rules["rule"]:
                iptc.easy.insert_rule("filter", "PINGATTACK", rule)
                print("Successfully added rule: %s." %rule)

        for ip in list.WHITELIST_ADDRESS:
            rule_block_icmp = {
                                "protocol": "icmp",
                                "icmp": {"icmp-type": "8"},
                                "dst": ip,
                                "target": "PINGATTACK",
                            }
            iptc.easy.insert_rule("filter", "INPUT", rule_block_icmp)
            print("Successfully added rule: %s." %rule_block_icmp)
    
    except iptc.IPTCError as error:
        print(error)

# output
# {"protocol": "tcp", "target": "DROP", "counters": [0, 0], "tcp": {"dport": "80"}}
# input 
# {"protocol": "tcp", "target": "DROP", "counters": [0, 0], "tcp": {"sport": "80"}}
def port_rules():
    try:
        rule_add_log = [{"rule": [
                                    {"target": "DROP"},
                                    {"target":
                                        {"LOG": {
                                            "log_prefix": "Denied http request!",
                                            "log_level": "7"
                                            }
                                        }
                                    }
                                ]
                            }
                    ]
        for rules in rule_add_log:
            for rule in rules["rule"]:
                iptc.easy.insert_rule("filter", "PORTATTACK", rule)
                print("Successfully added rule: %s." %rule)

        outcoming_tcp = [{"rule":[
                                    {
                                        "protocol": "tcp",
                                        "target": "PORTATTACK",
                                        "tcp": {"dport": "80"}, 
                                    },
                                    {
                                        "state": {"state": "NEW"},
                                        "protocol": "tcp",
                                        "tcp": {"dport": "80"},
                                    }
                                ]
                            }
                        ]
        for rules in outcoming_tcp:
            for rule in rules["rule"]:
                iptc.easy.insert_rule("filter", "OUTPUT", rule)
                print("Successfully added rule: %s." %rule)

        #{"tcp": {"dport": ["!", "22"]}, "target": "DROP", "counters": [10, 400], "protocol": "tcp"}
        incoming_tcp = [{"rule":[
                                        {
                                            "protocol": "tcp",
                                            "target": "PORTATTACK",
                                            "tcp": {"sport": "80"},
                                        },
                                        {
                                            "state": {"state": "NEW"},
                                            "protocol": "tcp",
                                            "tcp": {"sport": "80"},
                                        }
                                    ]
                                }
                            ]

        for rules in incoming_tcp:
            for rule in rules["rule"]:
                iptc.easy.insert_rule("filter", "INPUT", rule)
                print("Successfully added rule: %s." %rule)

    except iptc.IPTCError as error:
        print(error)

if __name__ == "__main__":
    add_chain()
    flush_chain()
    forward()
    ssh_rules()
    block_icmp()
    #port_rules()
    connection_attempt()

#tcp&udp - input
#{"in-interface": "wlan0", "counters": [245, 15528], "protocol": "tcp", "target": "ACCEPT", "tcp": {"dport": "22"}}, 
# {"in-interface": "wlan0", "counters": [0, 0], "protocol": "tcp", "target": "ACCEPT", "tcp": {"dport": "443"}}, 
# {"in-interface": "wlan0", "udp": {"dport": "53"}, "protocol": "udp", "counters": [1, 69], "target": "ACCEPT"}]

#tcp output
#[{"target": "DROP", "protocol": "icmp", "icmp": {"icmp-type": "0"}, "counters": [0, 0]}, {"target": "ACCEPT", "protocol": "tcp", "counters": [0, 0], "out-interface": "wlan0", "tcp": {"dport": "22"}}]
