import sys
import string
from colorama import Back, Fore, Style, init

init()


def cprint(*args, color=Fore.RESET, mark='*', sep=' ', end='\n', frame_index=1, **kwargs):
    frame = sys._getframe(frame_index)

    colors = {
        'bgreen': Fore.GREEN + Style.BRIGHT,
        'bred': Fore.RED + Style.BRIGHT,
        'bblue': Fore.BLUE + Style.BRIGHT,
        'byellow': Fore.YELLOW + Style.BRIGHT,
        'green': Fore.GREEN,
        'red': Fore.RED,
        'blue': Fore.BLUE,
        'yellow': Fore.YELLOW,
        'bright': Style.BRIGHT,
        'srst': Style.NORMAL,
        'crst': Fore.RESET,
        'rst': Style.NORMAL + Fore.RESET
    }

    colors.update(frame.f_globals)
    colors.update(frame.f_locals)
    colors.update(kwargs)

    unfmt = ''

    if mark is not None:
        unfmt += f'{color}[{Style.BRIGHT}{mark}{Style.NORMAL}]{Fore.RESET}{sep}'

    unfmt += sep.join(args)

    fmted = unfmt

    for attempt in range(10):
        try:
            fmted = string.Formatter().vformat(unfmt, args, colors)

            break
        except KeyError as e:
            key = e.args[0]

            unfmt = unfmt.replace('{' + key + '}', '{{' + key + '}}')

    print(fmted, sep=sep, end=end)


def info(*args, sep=' ', end='\n', **kwargs):
    cprint(*args, color=Fore.GREEN, mark='*', sep=sep, end=end, frame_index=2, **kwargs)


def warn(*args, sep=' ', end='\n', **kwargs):
    cprint(*args, color=Fore.YELLOW, mark='!', sep=sep, end=end, frame_index=2, **kwargs)


def error(*args, sep=' ', end='\n', **kwargs):
    cprint(*args, color=Fore.RED, mark='!', sep=sep, end=end, frame_index=2, **kwargs)


def fail(*args, sep=' ', end='\n', **kwargs):
    cprint(*args, color=Fore.RED, mark='!', sep=sep, end=end, frame_index=2, **kwargs)

    exit(1)


def tally(*args, color=Fore.BLUE, mark='>>>', sep=' ', end='\n', **kwargs):
	cprint(color + f'{bright}{mark}{rst}', *args, mark=None, sep=sep, end=end, frame_index=2, **kwargs)
