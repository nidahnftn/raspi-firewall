allow_ssh = ['10.10.10.7']
whitelist_address = ['10.10.10.7', '10.10.10.13', '10.10.10.11']
# ports remote can access from local
INPUT_ALLOWED_UDP_SPORTS = [53]
INPUT_ALLOWED_TCP_SPORTS = [443, 22]
# ports local can access from remote
INPUT_ALLOWED_TCP_DPORTS = [22]