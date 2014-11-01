#!/usr/bin/env python

"""push.py - Send a notification using Pushover"""

# Alternatives: https://github.com/Wyattjoh/pushover (clean, nothing special)
# https://pypi.python.org/pypi/pushnotify/0.5.1 (supports multiple notification systems)

# TODO: command line options to validate API token or user key

# TODO: message from stdin

# TODO: validate url (512 char max)
# - urlparse module?
# TODO: validate url title (100 char max)

# TODO: handle response (# messages remaining, etc)
# TODO: handle callback urls
# TODO: handle receipts

# TODO: get KEYs from environment?
# - or through command line
# - or through config file (best option??)
#   - if config file doesn't exist, you could prompt the user for those values
#   and create one

__version__ = '1.0'
__author__ = "Brian Connelly"
__copyright__ = "Copyright (c) 2014 Brian Connelly"
__credits__ = ["Brian Connelly"]
__license__ = "MIT"
__maintainer__ = "Brian Connelly"
__email__ = "bdc@bconnelly.net"
__status__ = "Beta"

import argparse
import ast
import httplib
import re
import socket
import sys
import urllib


def valid_app_token(token):
    if re.match(r'^[a-zA-Z0-9]{30}$', token):
        return True
    else:
        return False

def valid_user_key(key):
    if re.match(r'^[a-zA-Z0-9]{30}$', key):
        # TODO: issue API call?
        # https://pushover.net/api#verification
        return True
    else:
        return False

def valid_group_key(key):
    return valid_user_key(key)


sound_choices = ['bike', 'bugle', 'cashregister', 'classical', 'cosmic',
                 'falling', 'gamelan', 'incoming', 'intermission', 'magic',
                 'mechanical', 'pianobar', 'siren', 'spacealarm', 'tugboat',
                 'alien', 'climb', 'persistent', 'echo', 'updown', 'pushover',
                 'none']

#try:
#    APP_TOKEN
#    USER_KEY
#except NameError as e:
#    print("Error: {e}".format(e=e))
#    print("Edit this script to add your specific APP_TOKEN and USER_KEY")
#    sys.exit(1)

parser = argparse.ArgumentParser(prog=sys.argv[0],
                                 description='Send a notification message with Pushover',
                                 epilog='Available Sounds: {s}'.format(s=', '.join(sound_choices)))
parser.add_argument('--version', action='version', version=__version__)
parser.add_argument('-d', '--device', metavar='D', help='send message to'\
                    ' specified device')
parser.add_argument('-t', '--title', metavar='t', help='message title')
parser.add_argument('-T', '--timestamp', metavar='T', help='send message ' \
                    'specified UNIX timestamp', type=float)
parser.add_argument('-u', '--url', metavar='u', help='supplementary URL for message')
parser.add_argument('-U', '--urltitle', metavar='U', help='title for '\
                    'supplementary url')
parser.add_argument('-s', '--sound', metavar='S', choices=sound_choices,
                    default='pushover', help='play specified sound (see below)')
parser.add_argument('--request', action='store_true', default=False,
                    help='print request token on success')

apigroup = parser.add_argument_group(title='Pushover API arguments (optional)',
                                     description='Specify alternate user or '\
                                     'API token')
apigroup.add_argument('--user', default='TODO', help='Pushover user or group'\
                      ' key (default: {x})'.format(x='TODO'))
apigroup.add_argument('--token', default='TODO', help='Application token '\
                      '(default: {x})'.format(x='TODO'))

pgroup = parser.add_argument_group(title='message priority (optional)',
                                   description='By default, messages send '\
                                   'with normal priority.')
pgroup.add_argument('--quiet', dest='priority', action='store_const',
                    const=-1, help='send as low priority (-1)')
pgroup.add_argument('--normal', dest='priority', action='store_const',
                    const=0, help='send as normal priority (0)')
pgroup.add_argument('--high', dest='priority', action='store_const', const=1,
                    help='send as high priority (1)')
pgroup.add_argument('--emergency', dest='priority', action='store_const',
                    const=2, help='send as emergency priority, requiring '\
                    'user confirmation (2)')
pgroup.add_argument('-r', '--retry', dest='retry', type=int,
                    default=30, help='Retry interval (seconds) for '\
                    'emergency messages (default: 30)')
pgroup.add_argument('-e', '--expire', dest='expire', type=int,
                    default=3600, help='Expiration time (seconds) for '\
                    'emergency messages (default: 3600)')

parser.add_argument('message', help='Message to send')
args = parser.parse_args()

if not valid_app_token(args.token):
    print("Error: Invalid application token")

if not valid_user_key(args.user):
    print("Error: Invalid user key")

urlargs = {"user": args.user, "token": args.token}

if args.title:
    if len(args.title) + len(args.message) > 512:
        print("Error: Maximum length for title and message is 512 characters")
else:
    if len(args.message) > 512:
        print("Error: Maximum length for title and message is 512 characters")

urlargs['message'] = args.message
urlargs['priority'] = args.priority

if args.priority == 2:
    urlargs['retry'] = args.retry
    urlargs['expire'] = args.expire

urlargs['sound'] = args.sound

if args.device:
    urlargs['device'] = args.device

if args.title:
    urlargs['title'] = args.title

if args.url:
    urlargs['url'] = args.url

if args.urltitle:
    urlargs['urltitle'] = args.urltitle

if args.timestamp:
    urlargs['timestamp'] = args.timestamp


conn = httplib.HTTPSConnection("api.pushover.net:443")
conn.request("POST", "/1/messages.json",
urllib.urlencode(urlargs, {"Content-type":
                           "application/x-www-form-urlencoded"}))
response = conn.getresponse()
data = response.read()

try:
    data_parsed = ast.literal_eval(data)
except SyntaxError as s:
    print "ERROR:",s
    if args.request and response.status == 200:
        print("Successfully sent message, however response could not be parsed")
        sys.exit(2)
    else:
        print("Error: Message not sent, and could not parse response")
        sys.exit(3)

if response.status == 200:
    if args.request:
        print(data_parsed['request'])
    sys.exit(0)
elif response.status == 429:
    print("Error: message limit reached")
    sys.exit(4)
elif floor(response.status/100) == 4:
    # TODO: handle the other 4xx errors
    # https://pushover.net/api#friendly
    pass
else:
    print("Error: Received status code {c}".format(c=data_parsed['status']))
    for e in data_parsed['errors']:
          print("Error: {e}".format(e=e))
    sys.exit(5)