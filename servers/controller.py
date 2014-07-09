#!/usr/bin/env python
from flask import Blueprint, session, render_template, url_for, request, redirect, flash, current_app as app
from pprint import pprint

server_app = Blueprint('servers', __name__, url_prefix='/servers')


@server_app.before_request
def before_request():
    request.mod = 'servers'


@server_app.route('/', methods=['GET'])
@server_app.route('/<active_type>', methods=['GET'])
def index(active_type=None):
    # load server types
    grouped_server = {}
    for server in app.db.servers.find():
        if server['type'] not in grouped_server:
            grouped_server[server['type']] = []
        grouped_server[server['type']].append(server)

    server_types = grouped_server.keys()
    return render_template('servers/index.html', config=app.config, grouped_server=grouped_server,
                           server_types=server_types, active_type=active_type)


@server_app.route('/add', methods=['POST'])
def server_add():
    server_name = request.form['txtNewServer']
    server_type = request.form['hfNewServerType']

    if app.db.servers.find_one({'server_name': server_name, 'type': server_type}) is None:
        server = {
            'server_name': server_name,
            'description': '',
            'ip_address': '',
            'port': '',
            'type': server_type,
            'advanced_config': '',
            'timeout': 3
        }
        app.db.servers.insert(server)
        flash('New server created.', 'message')
    else:
        flash('server %s.%s already exists.' % (server_type, server_name), 'error')

    return redirect(url_for('.index', active_type=server_type))


@server_app.route('/delete/<server_id>', methods=['POST'])
def server_delete(server_id):
    return redirect(url_for('.index', active_type=server_type))


@server_app.route('/sample', methods=['GET'])
def sample():
    return render_template('test_page.html')