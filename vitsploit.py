import socket
from webscan import WebScan
from exscan import exscan
from printer import cprint, fail


def check_host(host):
	try:
	    socket.setdefaulttimeout(10)

	    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	    s.connect((target, 80))
	except OSError:
	    return False
	else:
	    s.close()

	    return True


cprint('{byellow}Vit{bred}sploit{rst}\n', mark=None)

target = input('Target IP: ')

if check_host(target):
	ws = WebScan()
	ws.scan_host(target)
	exscan(target)

else:
	fail('Invalid IP.')
