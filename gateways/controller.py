#!/usr/bin/env python
from flask import Blueprint, session, render_template, url_for, request, redirect, flash, current_app as app
from bson.objectid import ObjectId
from bson.json_util import dumps
from pprint import pprint
import os

viewbag = dict()
viewbag['module_name'] = 'gateways'

bp_app = Blueprint(viewbag['module_name'], __name__, url_prefix='/%s' % viewbag['module_name'])


@bp_app.before_request
def before_request():
    request.mod = viewbag['module_name']


@bp_app.route('/', methods=['GET'])
def index():
    gateways = app.db.gateways.find()

    grouped_server = {}
    for server in app.db.servers.find():
        if server['type'] not in grouped_server:
            grouped_server[server['type']] = []
        grouped_server[server['type']].append(server)

    server_types = grouped_server.keys()
    sel_gateway_info = None

    if 'gateway_id' in session:
        viewbag['selected_gateway'] = session['gateway_id']
        sel_gateway_info = app.db.gateways.find_one({'_id': ObjectId(session['gateway_id'])})
    if 'sel_server_type' in session:
        viewbag['selected_server_type'] = session['sel_server_type']

    lookups = {}
    modules = {'gateway': []}
    for _module in os.listdir('%s/modules' % app.portal_installation_path):
        _module_split = _module.split('_')
        if _module_split[0] in 'gateway':
            modules[_module_split[0]].append(_module)
    lookups['modules'] = modules

    return render_template('gateways/index.html', viewbag=viewbag, gateways=gateways, server_types=server_types,
                           sel_gateway_info=sel_gateway_info, modules=lookups['modules']['gateway'])


@bp_app.route('/add', methods=['POST'])
def gateways_add():
    gateway_name = request.form['txt_new_gateway']

    if app.db.gateways.find_one({'gateway_name': gateway_name}) is None:
        gateway = {
            'gateway_name': gateway_name,
            'description': '',
            'advanced_config': '',
            'module': '',
            'ip_address': '',
            'servers': {}
        }
        new_id = app.db.gateways.insert(gateway)
        session['gateway_id'] = str(new_id)
        session['sel_server_type'] = ''
        flash('Gateway <strong>%s</strong> created' % gateway_name, 'message')
    else:
        flash('Gateway <strong>%s</strong> already exists' % gateway_name, 'error')

    return redirect(url_for('.index'))


@bp_app.route('/delete/<gateway_id>', methods=['POST'])
def gateways_delete(gateway_id):
    gateway = app.db.gateways.find_one({'_id': ObjectId(gateway_id)})
    if gateway is None:
        return redirect(url_for('.index'))

    if app.db.networks.find({'gateway_id': ObjectId(gateway_id)}).count() == 0:
        app.db.gateways.remove({'_id': ObjectId(gateway_id)})
        flash('Gateway <strong>%s</strong> deleted.' % (gateway['gateway_name']), 'message')
    else:
        flash('Unable to delete <strong>%s</strong>. Gateway is currently in use.' % (gateway['gateway_name']), 'message')

    return redirect(url_for('.index'))


@bp_app.route('/property/<gateway_id>', methods=['GET'])
def gateways_load(gateway_id):
    gateway = app.db.gateways.find_one({'_id': ObjectId(gateway_id)})
    # lookups = {}
    # modules = {'gateway': []}
    # for _module in os.listdir('%s/modules' % app.portal_installation_path):
    #     _module_split = _module.split('_')
    #     if _module_split[0] in 'gateway':
    #         modules[_module_split[0]].append(_module)
    # lookups['modules'] = modules
    # gateway['modules'] = lookups['modules']['gateway']
    return dumps(gateway)


@bp_app.route('/save', methods=['POST'])
def gateways_save():
    gateway_id = request.form['hf_sel_gateway']
    if gateway_id is None or gateway_id == '':
        return redirect(url_for('.index'))

    gateway = app.db.gateways.find_one({'_id': ObjectId(gateway_id)})
    if gateway is None:
        return redirect(url_for('.index'))

    session['gateway_id'] = str(gateway_id)
    session['sel_server_type'] = ''

    new_gateway = {
        'gateway_name': request.form.get('t_gateway_name'),
        'ip_address': request.form.get('t_ip_address'),
        'module': request.form.get('ddl_module'),
        'advanced_config': request.form.get('tAdvConfig')
    }

    app.db.gateways.update({'_id': ObjectId(gateway_id)}, {'$set': new_gateway})
    flash('Gateway <strong>%s</strong> updated.' % (gateway['gateway_name']), 'message')

    return redirect(url_for('.index'))


@bp_app.route('/load/servers/<gateway_id>/<server_type>', methods=['GET'])
def servers_load(gateway_id, server_type):
    gateway = app.db.gateways.find_one({'_id': ObjectId(gateway_id)})

    multilist_html = '<select class="multiselect" multiple="multiple" id="ml_servers" name="ml_servers">'
    for server in app.db.servers.find({'type': server_type}):
        selected_tag = ''
        if server_type in gateway['servers']:
            if str(server['_id']) in gateway['servers'][server_type]:
                selected_tag = 'selected'

        multilist_html += '<option value="%s" %s>%s</option>' % (server['_id'], selected_tag, server['server_name'])
    multilist_html += '</select>'
    return multilist_html


@bp_app.route('/save/servers', methods=['POST'])
def servers_save():
    servers = request.form.getlist('ml_servers')
    gateway_id = request.form['hf_sel_gateway']
    if gateway_id is None or gateway_id == '':
        return redirect(url_for('.index'))

    sel_server_type = request.form.get('hf_sel_servtype')
    if sel_server_type is None or sel_server_type == '':
        return redirect(url_for('.index'))

    gateway = app.db.gateways.find_one({'_id': ObjectId(gateway_id)})
    if gateway is None:
        return redirect(url_for('.index'))

    session['gateway_id'] = gateway_id
    session['sel_server_type'] = sel_server_type

    gateway['servers'][sel_server_type] = servers
    app.db.gateways.save(gateway)

    flash('Servers updated for <strong>%s</strong>.' % sel_server_type, 'message')
    return redirect(url_for('.index'))


# ** Pending:
# 3. modules dropdownlist populate
# 4. modules save in gateway document