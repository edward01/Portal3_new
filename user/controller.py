#!/usr/bin/env python
from flask import Blueprint, session, render_template, url_for, request, redirect, flash, current_app as app

user_app = Blueprint('user', __name__)


@user_app.before_request
def before_request():
	request.mod = 'user'


@user_app.route('/', methods=['GET'])
@user_app.route('/login', methods=['GET'])
def login_form():
    return render_template('user/login.html')


@user_app.route('/', methods=['POST'])
@user_app.route('/login', methods=['POST'])
def login_submit():
    username = request.form['username']
    password = request.form['password']

    if username in app.passwd and app.passwd[username] == password:
        session['authorized'] = True
        session['username'] = username
        return redirect(url_for('index'))
    else:
        if username == '' or password == '':
            flash('Username or Password is required.')
        else:
            flash('Access Denied.')
        return render_template('user/login.html')


@user_app.route('/logout', methods=['GET'])
def logout():
    session.clear()
    return redirect(url_for('.login_form'))