#!/usr/bin/env python
from flask import Blueprint, session, render_template, url_for, request, redirect, flash, current_app as app
from bson.objectid import ObjectId
from bson.json_util import dumps
from pprint import pprint

viewbag = dict()
viewbag['module_name'] = 'gateways'

bp_app = Blueprint(viewbag['module_name'], __name__, url_prefix='/%s' % viewbag['module_name'])


@bp_app.before_request
def before_request():
    request.mod = viewbag['module_name']


@bp_app.route('/', methods=['GET'])
def index():
    return render_template('gateways/index.html', config=app.config, viewbag=viewbag)

