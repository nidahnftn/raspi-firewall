import iptc
import list
#new file in ports.py
tables = ["filter", "mangle", "raw"]
chains = ["POSTROUTING", "INPUT", "OUTPUT", "FORWARD"] 
new_chains = ["SSHATTACK", "PORTATTACK"]

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
    #get_nat_chain = iptc.Chain("nat", "POSTROUTING")
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
    #get_ff_chain = iptc.Chain("filter", "FORWARD")
    try:
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
                iptc.easy.insert_rule("filter", "FORWARD", rule)
                print("Successfully added rule: %s." %rule)
    
    except iptc.IPTCError as error:
        print(error)

# disable icmp request for raspi and iot devices
def ssh_rules():
    #get_ssh_chain = iptc.Chain("filter", "SSHATTACK")
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

        #get_fi_chain = iptc.Chain("filter", "INPUT")
        for ip in list.WHITELIST_ADDRESS:
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
    #get_icmp_chain = iptc.Chain("filter", "INPUT")
    try:
        rule_block_icmp = {
                            "protocol": "icmp", 
                            "target": "DROP",
                            "in-interface": "wlan0", 
                        }
        iptc.easy.insert_rule("filter", "INPUT", rule_block_icmp)
        print("Successfully added rule: %s." %rule_block_icmp)
    
    except iptc.IPTCError as error:
        print(error)

def port_rules():
    #get_port_chain = iptc.Chain("filter", "PORTATTACK")
    try:
        rule_add_log = [{"rule": [
                                    {"target": "DROP"},
                                    {"target":
                                        {"LOG": {
                                            "log_prefix": "Possible PORT attack!",
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

        #get_fi_chain = iptc.Chain("filter", "INPUT")
        for port in list.OUTPUT_ALLOWED_UDP_SPORTS:
            incoming_udp = [{"rule":[
                                            {
                                                "protocol": "udp",
                                                "target": "PORTATTACK",
                                                "udp": {"sport": ["!", port]}, 
                                            },
                                            {
                                                "state": {"state": "NEW"},
                                                "protocol": "udp",
                                                "udp": {"sport": ["!", port]},
                                            }
                                        ]
                                    }
                                ]

            for rules in incoming_udp:
                for rule in rules["rule"]:
                    iptc.easy.insert_rule("filter", "OUTPUT", rule)
                    print("Successfully added rule: %s." %rule)

        for port in list.OUTPUT_ALLOWED_TCP_SPORTS:
            incoming_tcp = [{"rule":[
                                            {
                                                "protocol": "tcp",
                                                "target": "PORTATTACK",
                                                "tcp": {"sport": ["!", port]}, 
                                            },
                                            {
                                                "state": {"state": "NEW"},
                                                "protocol": "tcp",
                                                "tcp": {"sport": ["!", port]},
                                            }
                                        ]
                                    }
                                ]

            for rules in incoming_tcp:
                for rule in rules["rule"]:
                    iptc.easy.insert_rule("filter", "OUTPUT", rule)
                    print("Successfully added rule: %s." %rule)

        #{"tcp": {"dport": ["!", "22"]}, "target": "DROP", "counters": [10, 400], "protocol": "tcp"}
        #get_fo_chain = iptc.Chain("filter", "OUTPUT")
        for port in list.INPUT_ALLOWED_TCP_DPORTS:
            outcoming_tcp = [{"rule":[
                                            {
                                                "protocol": "tcp",
                                                "target": "PORTATTACK",
                                                "tcp": {"dport": ["!", port]},
                                            },
                                            {
                                                "state": {"state": "NEW"},
                                                "protocol": "tcp",
                                                "tcp": {"dport": ["!", port]},
                                            }
                                        ]
                                    }
                                ]

            for rules in outcoming_tcp:
                for rule in rules["rule"]:
                    iptc.easy.insert_rule("filter", "INPUT", rule)
                    print("Successfully added rule: %s." %rule)

    except iptc.IPTCError as error:
        print(error)

if __name__ == "__main__":
    add_chain()
    flush_chain()
    # nat()
    forward()
    ssh_rules()
    block_icmp()
    #port_rules()

#tcp&udp - input
#{"in-interface": "wlan0", "counters": [245, 15528], "protocol": "tcp", "target": "ACCEPT", "tcp": {"dport": "22"}}, 
# {"in-interface": "wlan0", "counters": [0, 0], "protocol": "tcp", "target": "ACCEPT", "tcp": {"dport": "443"}}, 
# {"in-interface": "wlan0", "udp": {"dport": "53"}, "protocol": "udp", "counters": [1, 69], "target": "ACCEPT"}]

#tcp output
#[{"target": "DROP", "protocol": "icmp", "icmp": {"icmp-type": "0"}, "counters": [0, 0]}, {"target": "ACCEPT", "protocol": "tcp", "counters": [0, 0], "out-interface": "wlan0", "tcp": {"dport": "22"}}]
