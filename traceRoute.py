import time
from scapy.all import *

resp = []
for t in range(1,25):
    ip = IP(dst='8.8.8.8', ttl=t, id=RandShort())
    ts = time.time()
    r = sr1(ip/ICMP(), retry=1, timeout=3)
    te = time.time()
    resp.append((t, r, (te-ts)*1000))
    if r and r.src == '8.8.8.8':
        break

print(len(resp), 'responses')
print('\n', resp[2])

for l in resp:
    print('{:2} {:8.3f} ms  '.format(l[0], l[2]), end='')
    if l[1]:
        print(l[1].src)
    else:
        print('*')