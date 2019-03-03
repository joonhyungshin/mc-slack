from flask import Flask, jsonify, request, Response
from mcstatus import MinecraftServer
from configparser import ConfigParser
from urllib.request import urlopen, Request
from threading import Thread
import hmac
import hashlib
import shlex
import json


app = Flask(__name__)


def verify_request():
    version = 'v0'
    config = ConfigParser()
    config.read('config.ini')
    signing_secret = config['SlackApp']['SigningSecret']
    x_slack_request_timestamp = request.headers.get('X-Slack-Request-Timestamp')
    x_slack_signature = request.headers.get('X-Slack-Signature')
    request_body = request.get_data().decode()
    base_string = '{}:{}:{}'.format(version, x_slack_request_timestamp, request_body)
    verifier = '{}={}'.format(version, hmac.new(signing_secret.encode(),
                                                base_string.encode(),
                                                hashlib.sha256).hexdigest())
    return hmac.compare_digest(verifier, x_slack_signature)


def slack_response(text, response_type='ephemeral', attachments=None):
    payload = {
        'response_type': response_type,
        'text': text
    }
    if attachments is not None:
        payload['attachments'] = attachments

    return jsonify(payload), 200


def send_slack_message(hook_url, payload):
    data = json.dumps(payload).encode()
    req = Request(hook_url, data)
    urlopen(req)


def send_mc_status(address, query_type, response_url, response_type='ephemeral'):
    print(address)
    server = MinecraftServer.lookup(address)
    try:
        if query_type == 'status':
            status = server.status()
            send_slack_message(response_url, {
                'response_type': response_type,
                'blocks': [
                    {
                        'type': 'section',
                        'text': {
                            'type': 'mrkdwn',
                            'text': 'Version: v{} (protocol {})'.format(status.version.name,
                                                                        status.version.protocol)
                        }
                    },
                    {
                        'type': 'section',
                        'text': {
                            'type': 'mrkdwn',
                            'text': 'Description: "{}"'.format(status.description)
                        }
                    },
                    {
                        'type': 'section',
                        'text': {
                            'type': 'mrkdwn',
                            'text': 'Players: {} / {} {}'.format(
                                status.players.online,
                                status.players.max,
                                [
                                 '{} ({})'.format(player.name, player.id)
                                 for player in status.players.sample
                                ] if status.players.sample is not None else 'No players online'
                            )
                        }
                    }
                ]
            })
        elif query_type == 'ping':
            ping = server.ping()
            send_slack_message(response_url, {
                'response_type': response_type,
                'text': 'Latency: {}ms'.format(ping)
            })
        elif query_type == 'query':
            query = server.query()
            send_slack_message(response_url, {
                'response_type': response_type,
                'blocks': [
                    {
                        'type': 'section',
                        'text': {
                            'type': 'mrkdwn',
                            'text': 'Host: {}:{}'.format(query.raw['hostip'], query.raw['hostport'])
                        }
                    },
                    {
                        'type': 'section',
                        'text': {
                            'type': 'mrkdwn',
                            'text': 'Software: v{} {}'.format(query.software.version, query.software.brand)
                        }
                    },
                    {
                        'type': 'section',
                        'text': {
                            'type': 'mrkdwn',
                            'text': 'Plugins: {}'.format(query.software.plugins)
                        }
                    },
                    {
                        'type': 'section',
                        'text': {
                            'type': 'mrkdwn',
                            'text': 'MOTD: "{}"'.format(query.motd)
                        }
                    },
                    {
                        'type': 'section',
                        'text': {
                            'type': 'mrkdwn',
                            'text': 'Players: {} / {} {}'.format(
                                query.players.online,
                                query.players.max,
                                query.players.names
                            )
                        }
                    }
                ]
            })

    except (OSError, ConnectionRefusedError, AttributeError):
        error_msg = 'Failed to fetch server data. '
        if query_type == 'query':
            error_msg += 'Perhaps the server does not allow queries?'
        else:
            error_msg += 'Perhaps there is a mistake in address?'

        send_slack_message(response_url, {
            'response_type': response_type,
            'text': error_msg
        })


def schedule_slack_response(address, query_type, response_url, response_type='ephemeral'):
    thread = Thread(target=send_mc_status,
                    args=(address, query_type, response_url),
                    kwargs={'response_type': response_type})
    thread.start()
    return thread


@app.route('/mcstatus', methods=['POST'])
def check_mc_status():
    if verify_request():
        cmd_args = shlex.split(request.form.get('text'))
        response_msg = ''
        response_url = request.form.get('response_url')
        query_list = ['status', 'ping', 'query']

        success = True
        response_type = 'ephemeral'

        if 2 <= len(cmd_args) <= 3:
            address = cmd_args[0]
            query_type = cmd_args[1]
            if len(cmd_args) == 3:
                if cmd_args[2] == 'channel':
                    response_type = 'in_channel'
                else:
                    response_msg = 'The third argument should be `channel`, or be omitted.'
                    success = False

            if success:
                if query_type in query_list:
                    response_msg = 'Requested `{}` data for server `{}`.'.format(query_type, address)
                    schedule_slack_response(address, query_type, response_url, response_type)
                else:
                    response_msg = 'The query type should be one of `status`, `ping`, and `query`.'
                    success = False
        else:
            response_msg = 'The command should contain 2 to 3 arguments.'
            success = False

        payload = {
            'response_type': response_type if success else 'ephemeral',
            'text': response_msg
        }
        return jsonify(payload), 200


if __name__ == '__main__':
    app.run()
