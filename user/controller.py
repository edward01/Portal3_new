#!/usr/bin/env python
from flask import Blueprint, session, render_template, url_for, request, redirect, flash, current_app as app
from pprint import pprint

user_app = Blueprint('user', __name__)



@user_app.route('/', methods=['GET'])
@user_app.route('/login', methods=['GET'])
def login_form():
    return render_template('user/login.html', config=app.config)


@user_app.route('/', methods=['POST'])
@user_app.route('/login', methods=['POST'])
def login_submit():
    username = request.form['username']
    password = request.form['password']

    users = app.db.users.find_one({'name': username, 'password': password})
    pprint(users)

    if users or (username in app.passwd and app.passwd[username] == password):
        session['authorized'] = True
        session['username'] = username
        return redirect(url_for('servers.index'))
    else:
        if username == '' or password == '':
            flash('Username or Password is required.', 'error')
        else:
            flash('Access Denied.', 'error')
        return render_template('user/login.html', config=app.config)


@user_app.route('/logout', methods=['GET'])
def logout():
    session['gateway_id'] = ''
    session['sel_server_type'] = ''
    session.clear()
    return redirect(url_for('.login_form'))