import socket
from colorama import Fore, Style, init
from webscan import WebScan
from exscan import exscan
from printer import cprint, fail

init()


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


def run():
	cprint('{byellow}Vit{bred}sploit{rst}\n', mark=None)

	target = input('{Style.BRIGHT}{Fore.RED}Target IP:{Fore.RESET} ')

	if check_host(target):
		ws = WebScan()
		ws.scan_host(target)
		exscan(target)

	else:
		fail('Invalid IP.')


try:
	run()
except KeyboardInterrupt:
	pass
