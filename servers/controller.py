#!/usr/bin/env python
from flask import Blueprint, session, render_template, url_for, request, redirect, flash, current_app as app
from bson.objectid import ObjectId
from bson.json_util import dumps
from pprint import pprint

server_app = Blueprint('servers', __name__, url_prefix='/servers')


@server_app.before_request
def before_request():
    request.mod = 'servers'


@server_app.route('/', methods=['GET'])
@server_app.route('/<active_type>', methods=['GET'])
@server_app.route('/<active_type>/<active_name>', methods=['GET'])
def index(active_type=None, active_name=None):
    # load server types
    grouped_server = {}
    for server in app.db.servers.find():
        if server['type'] not in grouped_server:
            grouped_server[server['type']] = []
        grouped_server[server['type']].append(server)

    server_types = grouped_server.keys()

    server_dtls = None
    if active_name is not None:
        server_dtls = app.db.servers.find_one({'_id': ObjectId(session['server_id'])})

    return render_template('servers/index.html', config=app.config, grouped_server=grouped_server,
                           server_types=server_types, active_type=active_type, active_name=active_name,
                           server_dtls=server_dtls)


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
        flash('New server <strong>%s</strong> created.' % server_name, 'message')
    else:
        flash('server <strong>%s.%s</strong> already exists.' % (server_type, server_name), 'error')

    return redirect(url_for('.index', active_type=server_type, active_name=server_name))


@server_app.route('/delete/<server_id>', methods=['POST'])
def server_delete(server_id):
    server_type = request.form['hf_selType']
    server = app.db.servers.find_one({'_id': ObjectId(server_id)})

    if server is None:
        return redirect(url_for('.index'))

    gateway_used_cnt = 0
    for gateway in app.db.gateways.find():
        if 'servers' in gateway:
            if server_id in gateway['servers']:
                gateway_used_cnt += 1

    if gateway_used_cnt == 0:
        app.db.servers.remove({'_id': ObjectId(server_id)})
        flash('Server <strong>%s</strong> deleted.' % (server['server_name']), 'message')
    else:
        flash('Unable to delete <strong>%s</strong>. Server is currently in use.' % (server['server_name']), 'message')

    return redirect(url_for('.index', active_type=server_type))


@server_app.route('/load/<server_id>', methods=['GET'])
def server_load(server_id):
    server = app.db.servers.find_one({'_id': ObjectId(server_id)})
    return dumps(server)


@server_app.route('/save', methods=['POST'])
def server_save():
    server_type = request.form['hf_selType']
    server_id = request.form['hf_selID']
    if server_id is None or server_id == '':
        return redirect(url_for('.index'))

    server = app.db.servers.find_one({'_id': ObjectId(server_id)})
    if server is None:
        return redirect(url_for('.index'))

    # for key in request.form:
    #     pprint(key)

    session['server_id'] = server_id


    new_server = {
        '_id': ObjectId(server_id),
        'description': '',
        'server_name': request.form.get('tServerName'),
        'advanced_config': request.form.get('tAdvConfig'),
        'ip_address': request.form.get('tIPAddress'),
        'timeout': request.form.get('tTimeout'),
        'shared_secret': request.form.get('tSharedSecret'),
        'type': server_type,
        'credentials': request.form.get('tCredentials'),
        'port': request.form.get('tPort'),
        'principal': request.form.get('tPrincipal')
    }

    app.db.servers.save(new_server)
    flash('Server <strong>%s</strong> updated.' % (server['server_name']), 'message')

    return redirect(url_for('.index', active_type=server_type, active_name=request.form.get('tServerName')))
