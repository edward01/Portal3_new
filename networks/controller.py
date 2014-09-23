#!/usr/bin/env python
from flask import Blueprint, session, render_template, url_for, request, redirect, flash, current_app as app
from bson.objectid import ObjectId
from bson.json_util import dumps
from pprint import pprint
import os

viewbag = dict()
viewbag['module_name'] = 'networks'

bp_app = Blueprint(viewbag['module_name'], __name__, url_prefix='/%s' % viewbag['module_name'])


@bp_app.before_request
def before_request():
	request.mod = viewbag['module_name']


@bp_app.route('/', methods=['GET'])
def index():
	networks = app.db.networks.find()
	return render_template('networks/index.html', viewbag=viewbag, networks=networks)


@bp_app.route('/add', methods=['POST'])
def networks_add():
	network_name = request.form['txt_new_network']

	if app.db.networks.find_one({'network_name': network_name}) is None:
		network = {
			'network_name': network_name,
			'active': False,
			'description': '',
			'subnets': [],
			'module': None,
			'template': None,
			'template_mobile': None,
			'advanced_config': ''
		}
		new_id = app.db.networks.insert(network)
		session['network_id'] = str(new_id)
		session['sel_network'] = ''
		flash('Network <strong>%s</strong> created' % network_name, 'message')
	else:
		flash('Network <strong>%s</strong> already exists' % network_name, 'error')

	return redirect(url_for('.index'))