#!/usr/bin/env python

"""push.py - Send a notification using Pushover"""

__version__ = '0.1'
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
import math
import re
import socket
import sys
import urllib


def valid_app_token(token):
    return re.match(r'^[a-zA-Z0-9]{30}$', token) != None

def valid_user_key(key):
    return re.match(r'^[a-zA-Z0-9]{30}$', key) != None

def valid_group_key(key):
    return valid_user_key(key)

def valid_device_name(device):
    return re.match(r'^[A-Za-z0-9_-]{1,25}$', device) != None


sound_choices = ['bike', 'bugle', 'cashregister', 'classical', 'cosmic',
                 'falling', 'gamelan', 'incoming', 'intermission', 'magic',
                 'mechanical', 'pianobar', 'siren', 'spacealarm', 'tugboat',
                 'alien', 'climb', 'persistent', 'echo', 'updown', 'pushover',
                 'none']


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
                                     description='Specify user or API token')
apigroup.add_argument('--user', default='TODO', help='Pushover user or group'\
                      ' key (default: {x})'.format(x='TODO'))
apigroup.add_argument('--token', default='TODO', help='Application token '\
                      '(default: {x})'.format(x='TODO'))

pgroup = parser.add_argument_group(title='message priority (optional)',
                                   description='By default, messages send '\
                                   'with normal priority.')
pgroup.add_argument('--silent', dest='priority', action='store_const',
                    const=-2, help='send as lowest priority (-2)')
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
    sys.exit(1)

if not valid_user_key(args.user):
    print("Error: Invalid user key")
    sys.exit(2)

urlargs = {"user": args.user, "token": args.token}

if args.title:
    if len(args.title) + len(args.message) > 512:
        print("Error: Maximum length for title and message is 512 characters")
        sys.exit(3)
    urlargs['title'] = args.title
else:
    if len(args.message) > 512:
        print("Error: Maximum length for title and message is 512 characters")
        sys.exit(4)

urlargs['message'] = args.message
urlargs['priority'] = args.priority

if args.priority == 2:
    if args.retry < 30:
        print("Error: Retry must be at least 30 seconds")
        sys.exit(5)

    if args.expire > 86400:
        print("Error: Expire can not be larger than 86400 seconds")
        sys.exit(6)

    urlargs['retry'] = args.retry
    urlargs['expire'] = args.expire

urlargs['sound'] = args.sound

if args.device:
    if not valid_device_name(args.device):
        print("Error: Invalid device name")
        sys.exit(5)

    urlargs['device'] = args.device


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
    if args.request and response.status == 200:
        print("Successfully sent message, however response could not be parsed")
        sys.exit(6)
    else:
        print("Error: Message not sent, and could not parse response")
        sys.exit(7)

if response.status == 200:
    if args.request:
        print(data_parsed['request'])
    sys.exit(0)
elif response.status == 429:
    print("Error: message limit reached")
    sys.exit(8)
elif math.floor(response.status/100) == 4:
    # TODO: handle the other 4xx errors
    # https://pushover.net/api#friendly
    pass
else:
    print("Error: Received status code {c}".format(c=data_parsed['status']))
    for e in data_parsed['errors']:
          print("Error: {e}".format(e=e))
    sys.exit(9)

