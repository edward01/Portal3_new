#!/usr/bin/env python
import os
import re
import datetime
from flask import Flask, render_template, redirect, url_for, request, session
from config import db_config
import pymongo_safe
import httplib2

from user.controller import user_app
from servers.controller import server_app

# user: admin
# password: iop-098


portal_installation_path = '%s/portal3_new/portal' % os.getcwd()

app = Flask('Portal3')
app.config.from_object('config')


# database
conn = pymongo_safe.MongoHandler(db_config)
app.db = conn['portal'].portal

# app.templates = db.templates
# app.template_properties = db.template_properties
# app.networks = db.networks
# app.gateways = db.gateways
# app.servers = db.servers
# app.zone_groups = db.zone_groups
# app.zones = db.zones
# app.zone_areas = {
# 'NMM': 'North Metro Manila',
#     'SMM': 'South Metro Manila',
#     'NL': 'North Luzon',
#     'CL': 'Central Luzon',
#     'SL': 'South Luzon',
#     'VS': 'Visayas',
#     'MD': 'Mindanao'
# }
# app.users = db.users
#
app.static_regex = re.compile('^.+\.(jpg|jpeg|gif|png|ico|css|zip|tgz|gz|rar|bz2|pdf|txt|tar|wav|bmp|rtf|js|flv|swf|html|htm)$')
app.secret_key = '\xc5\xa4T\xa7\x13\xa0\x93\x0f\x0e\x8a|Fdtk\x92\x08\x8aFT\xc0\xcf\x05\x11'
app.permanent_session_lifetime = datetime.timedelta(minutes=15)
app.session_cookie_name = 'admin_sessid'
app.session_name = 'portal3_admin'

#
# app.debug = True
# app.jinja_env.add_extension('jinja2.ext.loopcontrols')
#
# network_properties = ['General', 'Network', 'Endpoints', 'Zones']
# gateway_properties = ['General', 'Servers']
# server_properties = ['General']
# server_types = ['AAA', 'SDB', 'BPC', 'SPS', 'Kenan', 'SDB_DBM', 'Datapower']
#
app.passwd = {
    'admin': 'iop-098',
}
# www = httplib2.Http()


# Blueprints...
# -------------------------------------------------------------------------------------------------------------------
app.register_blueprint(user_app)
app.register_blueprint(server_app)


# @app.before_request
# def before_request():
#     if request.endpoint is None and app.static_regex.match(request.path):
#         path_split = request.path.split('/')
#         for static_folder in ('css', 'font', 'img', 'js'):
#             try:
#                 return redirect(os.path.join('/static', '/'.join(path_split[path_split.index(static_folder):])))
#             except:
#                 continue
#
#     if 'username' not in session and request.endpoint not in ('login_form', 'login_submit', 'static'):
#         return redirect(url_for('login_form'))


@app.before_request
def before_request():
    print request.endpoint
    print session

    if request.endpoint != 'static':
        if request.endpoint not in ('user.login_form', 'user.login_submit') and 'authorized' not in session:
            return redirect(url_for('user.login_form'))

    # if request.endpoint in ('user.login_form', 'user.login_submit') and 'authorized' in session:
    #     return redirect(url_for('user.login_form'))

    print('-------------------BEFORE REQUEST-------------------')


@app.errorhandler(404)
def not_found(error):
    return render_template('error.html'), 404


@app.route('/')
def index():
    return redirect(url_for('user.login_form'))



@app.route('/sample', methods=['GET'])
def sample():
    return render_template('test_page.html')

@app.route('/sample2', methods=['GET'])
def sample2():
    return render_template('test_page2.html')


if __name__ == '__main__':
    app.run(debug=True)