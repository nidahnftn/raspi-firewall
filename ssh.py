from pickle import TRUE
import iptc
import list

def ssh_rules():
    table = iptc.Table(iptc.Table.FILTER)
    chain = iptc.Chain(table, "SSHATTACK")
    rule = iptc.Rule()
    targets = [{"target":
                [
                    {"DROP"},
                    {"LOG": {
                        "log_prefix": "Possible SSH attack!",
                        "log_level": "7"
                        }
                    }
               ]
            }
        ]

    for target in targets[0]["target"]:
        rule.target = iptc.Target(rule, target)
        chain.insert_rule(rule)

ssh_rules()