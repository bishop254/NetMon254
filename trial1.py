import time, threading
from scapy.all import sniff

e = threading.Event()

def _sniff(e):
    a = sniff(filter="tcp", stop_filter=lambda p: e.is_set())
    print("Stopped after %i packets" % len(a))

print("Start capturing thread")
t = threading.Thread(target=_sniff, args=(e,))
t.start()

time.sleep(3)
print("Try to shutdown capturing...")
e.set()

# This will run until you send a HTTP request somewhere
# There is no way to exit clean if no package is received
while True:
	t.join(2)
	if t.is_alive():
		print("Thread is still running...")
	else:
		break

print("Shutdown complete!")