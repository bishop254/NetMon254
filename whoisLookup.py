# from scapy.all import *

# hostname = 'google.com'

# for i in range(1, 28):
#     pkt = IP(dst=hostname, ttl=i) / UDP(dport=33434)
#     reply = sr1(pkt, verbose=0)
    
#     if reply is None:
#         break
#     elif reply.type == 3:
#         print('Done...' + reply.src)
#         break
#     else:
#         print('{} hops away...{}'.format(i, reply.src))

import whois

def is_registered(domain_name):
    try:
        w = whois.whois(domain_name)
    except Exception:
        return False
    else:
        return bool(w.domain_name)

domains = [
    "thepythoncode.com",
    "google.com",
    "github.com",
    "unknownrandomdomain.com",
    "www.laikipia.ac.ke",
    "portal.laikipia.ac.ke",
    "facebook.com"
]

for domain in domains:
    print('\n', '.................', '\n')
    print(domain, 'is registered.' if is_registered(domain) else 'is not registered')
    
    if is_registered(domain):
        whois_info = whois.whois(domain)
        print('Domain registrar: ', whois_info.registrar)
        print('WHOIS Server: ', whois_info.whois_server)
        print("Domain creation date:", whois_info.creation_date)
        print("Expiration date:", whois_info.expiration_date)