import sys

from termcolor import colored

from scandyCore import ScandyCore


def main():
    try:
        f = ScandyCore()
    except PermissionError:
        sys.exit(f"\n{colored('Run the program with sudo or administrator priveledges', 'red')}")


if __name__ == '__main__':
    main()
