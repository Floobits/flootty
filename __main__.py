import os
import optparse

parser = optparse.OptionParser()

parser.add_option("--user",
    dest="user",
    help="your username")

parser.add_option("--room",
    dest="room",
    help="the room to join")


parser.add_option("--owner",
    dest="owner",
    help="the room's owner to join")

parser.add_option("--room",
    dest="room",
    help="the roomm to join")


def load_floorc():
    """try to read settings out of the .floorc file"""
    s = {}
    try:
        fd = open(os.path.expanduser('~/.floorc'), 'rb')
    except IOError as e:
        if e.errno == 2:
            return s
        raise

    default_settings = fd.read().split('\n')
    fd.close()

    for setting in default_settings:
        sep = setting.find('=')
        if sep <= 0:
            continue
        name = setting[:sep]
        value = setting[sep + 1:]
        s[name] = value
    return s


def main():
    settings = load_floorc()


if __name__ == '__main__':
    main()
