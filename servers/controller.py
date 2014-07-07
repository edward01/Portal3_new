#!/usr/bin/env python
from flask import Blueprint, session, render_template, url_for, request, redirect, flash, current_app as app

server_app = Blueprint('servers', __name__, url_prefix='/servers')


@server_app.before_request
def before_request():
    request.mod = 'servers'


@server_app.route('/', methods=['GET'])
def index():
    return render_template('servers/index.html')
