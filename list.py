WHITELIST_ADDRESS = ['10.10.10.7']
BLACKLIST_ADDRESS = [
                    '10.10.10.1',  '10.10.10.2',  '10.10.10.3',  '10.10.10.4',  '10.10.10.5', 
                    '10.10.10.6',  '10.10.10.7',  '10.10.10.8',  '10.10.10.9',  '10.10.10.10', 
                    '10.10.10.11',  '10.10.10.12',  '10.10.10.13',  '10.10.10.14'
                ]
# ports remote can access from local
OUTPUT_ALLOWED_UDP_SPORTS = [53]
OUTPUT_ALLOWED_TCP_SPORTS = [443, 22]
# ports local can access from remote
INPUT_ALLOWED_TCP_DPORTS = [22]