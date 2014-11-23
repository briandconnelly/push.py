#!/usr/bin/env python

"""push.py - Send a notification using Pushover"""

__version__ = "0.1"
__author__ = "Brian Connelly"
__copyright__ = "Copyright (c) 2014 Brian Connelly"
__credits__ = ["Brian Connelly"]
__license__ = "MIT"
__maintainer__ = "Brian Connelly"
__email__ = "bdc@bconnelly.net"
__status__ = "Beta"

import argparse
import ast
import datetime
import json
import os
import re
import socket
import sys
import urllib

try:
    from httplib import HTTPSConnection
except ImportError:
    from http.client import HTTPSConnection

try:
    from urllib import urlencode
except ImportError:
    from urllib.parse import urlencode


def valid_app_token(token):
    """Check if the given app token is in the right format"""
    return re.match(r'^[a-zA-Z0-9]{30}$', token) != None


def valid_user_key(key):
    """Check if the given user key is in the right format"""
    return re.match(r'^[a-zA-Z0-9]{30}$', key) != None


def valid_message_receipt(receipt):
    """Check if the given message receipt is in the right format"""
    return re.match(r'^[a-zA-Z0-9]{30}$', receipt) != None


def valid_group_key(key):
    """Check if the given group key is in the right format"""
    return valid_user_key(key)


def valid_device_name(device):
    """Check if the given device name is in the right format"""
    return re.match(r'^[A-Za-z0-9_-]{1,25}$', device) != None


def request(method, route, data=None):
    if data is None:
        data = {}
    sroute = '/'.join(['/1'] + route)
    content = urlencode(data, {"Content-type": "application/x-www-form-urlencoded"})

    try:
        conn = HTTPSConnection("api.pushover.net")
        conn.request(method, sroute, content)
        response = conn.getresponse()
        data = json.loads(response.read().decode())
        return (response.status, data)
    except:
        raise Exception("problem")


def parse_arguments():
    """Parse command line arguments"""

    sound_choices = ['bike', 'bugle', 'cashregister', 'classical', 'cosmic',
                     'falling', 'gamelan', 'incoming', 'intermission',
                     'magic', 'mechanical', 'pianobar', 'siren', 'spacealarm',
                     'tugboat', 'alien', 'climb', 'persistent', 'echo',
                     'updown', 'pushover', 'none']

    parser = argparse.ArgumentParser(prog=sys.argv[0],
                                     description='Send a notification message with Pushover',
                                     epilog='Available Sounds: {s}'.format(s=', '.join(sound_choices)))
    parser.add_argument('--version', action='version', version=__version__)

    mgroup = parser.add_argument_group(title='message arguments')
    mgroup.add_argument('-d', '--device', metavar='D', help='send message to' \
                        ' specified device')
    mgroup.add_argument('-t', '--title', metavar='t', help='message title')
    mgroup.add_argument('-T', '--timestamp', metavar='T', help='send message ' \
                        'specified UNIX timestamp', type=float)
    mgroup.add_argument('-u', '--url', metavar='u',
                        help='supplementary URL for message')
    mgroup.add_argument('-U', '--urltitle', metavar='U', help='title for '\
                        'supplementary url')
    mgroup.add_argument('-s', '--sound', metavar='S', choices=sound_choices,
                        default='pushover', help='play specified sound (see below)')
    mgroup.add_argument('--request', action='store_true', default=False,
                        help='print request token on success')
    mgroup.add_argument('--validate', action='store_true', default=False,
                        help='validate the given user token (and device)')

    apigroup = parser.add_argument_group(title='Pushover API arguments (optional)',
                                         description='Specify user or API token')
    apigroup.add_argument('--user', help='Pushover user or group key')
    apigroup.add_argument('--token', help='Application token')

    pgroup = parser.add_argument_group(title='message priority (optional)',
                                       description='By default, messages send'\
                                       ' with normal priority.')
    pgroup.add_argument('--silent', dest='priority', action='store_const',
                        const=-2, help='send as lowest priority (-2)')
    pgroup.add_argument('--quiet', dest='priority', action='store_const',
                        const=-1, help='send as low priority (-1)')
    pgroup.add_argument('--normal', dest='priority', action='store_const',
                        const=0, help='send as normal priority (0)')
    pgroup.add_argument('--high', dest='priority', action='store_const',
                        const=1, help='send as high priority (1)')
    pgroup.add_argument('--emergency', dest='priority', action='store_const',
                        const=2, help='send as emergency priority, requiring '\
                        'user confirmation (2)')
    pgroup.add_argument('-r', '--retry', dest='retry', type=int,
                        default=30, help='Retry interval (seconds) for '\
                        'emergency messages (default: 30)')
    pgroup.add_argument('-e', '--expire', dest='expire', type=int,
                        default=3600, help='Expiration time (seconds) for '\
                        'emergency messages (default: 3600)')
    pgroup.add_argument('--callback', dest='callback', help='Callback URL for'\
                        ' emergency messages')

    egroup = parser.add_argument_group(title='emergency message receipts ' \
                                       '(optional)')
    egroup.add_argument('--receipt', metavar='R', help='check status of ' \
                        'emergency message with receipt R')
    egroup.add_argument('--cancel', metavar='R', help='cancel emergency '\
                        'message with receipt R')

    mgroup.add_argument('message', nargs='?', help='Message to send')

    args = parser.parse_args()

    return args


def main():
    args = parse_arguments()

    token = args.token
    if token is None:
        token = os.environ.get('PUSHPY_TOKEN')
        if token is None:
            print("Error: Must provide application token.")
            sys.exit(11)

    if not valid_app_token(token):
        print("Error: Invalid application token")
        sys.exit(1)

    user = args.user
    if user is None:
        user = os.environ.get('PUSHPY_USER')
        if user is None:
            print("Error: Must provide application token.")
            sys.exit(11)

    if not valid_user_key(user):
        print("Error: Invalid user/group key")
        sys.exit(2)

    urlargs = {"user": user, "token": token}


    # Check the status of an emergency message
    if args.receipt is not None:
        if not valid_message_receipt(args.receipt):
            print("Error: Invalid message receipt")
            sys.exit(41)

        try:
            st_query = "{r}.json?token={t}".format(r=args.receipt, t=token)
            (rstatus, rdata) = request("GET", ["receipts", st_query],
                                       data=None)
        except:
            print("Error: Could not connect to service")
            sys.exit(21)

        if rstatus == 200 and rdata['status'] == 1:
            print("Last Delivered At: {}".format(datetime.datetime.fromtimestamp(rdata["last_delivered_at"]).strftime('%Y-%m-%d %H:%M:%S %Z')))
            if rdata["acknowledged"] == 1:
                print("Acknowledged At: {}".format(datetime.datetime.fromtimestamp(rdata["acknowledged_at"]).strftime('%Y-%m-%d %H:%M:%S %Z')))
                print("Acknowledged By: {}".format(rdata["acknowledged_by"]))
            else:
                print("Not Acknowledged")

            if rdata["expired"]:
                print("Expired At: {}".format(datetime.datetime.fromtimestamp(rdata["expires_at"]).strftime('%Y-%m-%d %H:%M:%S %Z')))
            else:
                print("Expires At: {}".format(datetime.datetime.fromtimestamp(rdata["expires_at"]).strftime('%Y-%m-%d %H:%M:%S %Z')))

            if rdata["called_back"] == 1:
                print("Called Back At: {}".format(datetime.datetime.fromtimestamp(rdata["called_back_at"]).strftime('%Y-%m-%d %H:%M:%S %Z')))

            sys.exit(0)
        else:
            for error in rdata['errors']:
                print("Error: {e}".format(e=error))
            sys.exit(rdata['status'])


    # Cancel a message
    if args.cancel is not None:
        if not valid_message_receipt(args.cancel):
            print("Error: Invalid message receipt")
            sys.exit(41)

        try:
            (rstatus, rdata) = request("POST",
                                       ["receipts", args.cancel, "cancel.json"],
                                       data=urlargs)
        except:
            print("Error: Could not connect to service")
            sys.exit(21)

        if rstatus == 200 and rdata["status"] == 1:
            sys.exit(0)
        else:
            for error in rdata['errors']:
                print("Error: {e}".format(e=error))
            sys.exit(rdata["status"])

    if args.device:
        if not valid_device_name(args.device):
            print("Error: Invalid device name")
            sys.exit(5)

        urlargs['device'] = args.device

    # Validate the user/group key and device (optional)
    if args.validate:
        try:
            (rstatus, rdata) = request("POST",
                                       ["users", "validate.json"],
                                       data=urlargs)
        except:
            print("Error: Could not connect to service")
            sys.exit(21)

        if rstatus == 200 and rdata["status"] == 1:
            if args.device:
                print("Valid user/group and device")
            else:
                print("Valid user/group")

            sys.exit(0)
        else:
            for error in rdata['errors']:
                print("Error: {e}".format(e=error))
            sys.exit(rdata["status"])


    if args.message is None:
        message = ''
        for line in sys.stdin:
            message += line
        message = message.rstrip()
    else:
        message = args.message


    if args.title:
        if len(args.title) + len(message) > 512:
            print("Error: Exceeded maximum length for title and message")
            sys.exit(3)
        urlargs['title'] = args.title
    else:
        if len(message) > 512:
            print("Error: Exceeded maximum length for title and message")
            sys.exit(4)

    urlargs['message'] = message
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

    if args.callback is not None and args.priority == 2:
        urlargs['callback'] = args.callback

    urlargs['sound'] = args.sound

    if args.url:
        urlargs['url'] = args.url

    if args.urltitle:
        urlargs['urltitle'] = args.urltitle

    if args.timestamp:
        urlargs['timestamp'] = args.timestamp


    # Send a message
    try:
        (response_status, response_data) = request('POST', ['messages.json'],
                                                   data=urlargs)
    except:
        print("Error: Could not connect to service")
        sys.exit(21)

    if response_status == 200 and response_data['status'] == 1:
        if args.priority == 2:
            print(response_data['receipt'])
        if args.request:
            print(response_data['request'])
    elif response_status == 500:
        print("Error: Unable to connect to service")
        sys.exit(500)
    elif response_status == 429:
        print("Error: Message limit reached")
        sys.exit(429)
    else:
        for error in response_data['errors']:
            print("Error: {e}".format(e=error))
        sys.exit(response_data['status'])


if __name__ == "__main__":
    main()

