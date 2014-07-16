### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### 
# Roaming Module
# ## ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ##
#

from flask import url_for as flask_url_for, request, make_response, render_template, render_template_string, flash, abort, session
from captcha import captcha
from piechart import PieChart
import utils, time, datetime, pymongo, json, re, roaming, pkgutil

partners = {}
for partner in [name for _, name, _ in pkgutil.iter_modules(['roaming'])]:
	g = __import__('roaming.%s' % (partner), fromlist=['*'])	
	try:
		partners[g.__name__] = g
	except Exception as ex:
		print 'Exception', ex
		continue
print 'Loaded Roaming Partners: ', partners

# endpoint with network path support
def url_for(endpoint):
	if type(request.view_args) == type({}) and 'path' in request.view_args:
		return '%s%s' % (request.view_args['path'], flask_url_for(endpoint))
	return flask_url_for(endpoint)
   	
# modified redirect from Werkzeug 0.8.1
def redirect(location, code=302, headers={}):
    """Return a response object (a WSGI application) that, if called,
    redirects the client to the target location.  Supported codes are 301,
    302, 303, 305, and 307.  300 is not supported because it's not a real
    redirect and 304 because it's the answer for a request with a request
    with defined If-Modified-Since headers.

    .. versionadded:: 0.6
       The location can now be a unicode string that is encoded using
       the :func:`iri_to_uri` function.

    :param location: the location the response should redirect to.
    :param code: the redirect status code. defaults to 302.
    """
    from werkzeug.wrappers import BaseResponse
    display_location = location
    if isinstance(location, unicode):
        from werkzeug.urls import iri_to_uri
        location = iri_to_uri(location)
    response = BaseResponse(
        '<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">\n'
        '<title>Redirecting...</title>\n'
        '<h1>Redirecting...</h1>\n'
        '<p>You should be redirected automatically to target URL: '
        '<a href="%s">%s</a>.  If not click the link.' %
        (location, display_location), code, mimetype='text/html')
    response.headers['Location'] = location
    for header_key, header_val in headers.iteritems():
    	response.headers[header_key] = header_val
    return response	
    
#
# Network Data Model
#
class Model:

	spiels = {
		'quota_depleted': "Your Smart Wi-Fi subscription has expired/has been fully consumed. To subscribe, click here: <a href='https://my.smart.com.ph'>https://my.smart.com.ph</a>.",
		'quota_depleted2': "You no longer have remaining WiFi credits. Please try to connect to the internet via 3G/HSDPA/WCDMA instead. You can try to check your remaining data credits by texting BAL send to 2200 (for Always ON), etc.",
		'account_suspended': "Welcome to PLDT-SMART Wi-Fi Zone!<br/><br/>Please settle your account's outstanding balance to continue using this WIFI service.",
		'incorrect_credentials': "Invalid username or password. Please try again, or if you don't have a WiFi account yet, click <a href='/register'>#URL/register</a>.",
		'system_timeout': "Sorry, the system is taking longer to respond. Please try again.",
		'incorrect_captcha': "Incorrect security validation.",
		'invalid_account': "Sorry, you don't have a Smart Wi-Fi account yet, Please register here: <a href='/register'>#URL/register</a>.",		
		'activation_code': 'Your PLDT-SMART Wi-Fi Zone Activation Code is: %s',
#		'activation_code': 'Your activation code is %s. Please go to the WiFi Portal Reg Menu, Enter mobile no, activation code and your desired password to complete ur request.',
		'incorrect_activation_code': "Incorrect Activation Code.",
		'invalid_password': """Sorry, your password did not meet the requirements. Please try another password.<br/><br/>
Please ensure that password has a minimum of eight (8) characters and must contain alphanumeric characters:	<br/>
<table>
	<tr><td>Description</td><td>Examples</td></tr>
	<tr><td>Letters</td><td>A, B, C, .. Z<br/>a, b, c, .. z</td></tr>
	<tr><td>Numbers</td><td>0, 1, 2, .. 9</td></tr>
</table>""",
		'lockout_warning': "Your account shall be locked when you enter an invalid password on your next attempt. Click on this link: <a href='/lost_password'>#URL/lost_password</a> to update your password to avoid it from being locked.",
		'lockout': "Your account has been locked. Please try again after 24 hours.",
		'logout': "You have successfully logged out of your WiFi Session.",
		'account_exists': "You already have an existing PLDT-Smart Wi-Fi account.",
		'password_match_error': "The passwords you entered did not match. Please try again.",
		'incorrect_old_password': "Your old password is incorrect.",
		'registration_sps_request_sent': "A message shall be sent to you via SMS regarding your Wi-Fi registration request.",
		'registration_pending_request': "You already have a pending registration request. An SMS shall be sent to you once processing of your request has been completed.",
		'change_password_sps_request_sent': "A message shall be sent to you via SMS regarding your change password request.",
		'change_password_pending_request': "You already have a pending change password request. An SMS shall be sent to you once processing of your request has been completed.",
		'change_password_interval_denied': 'You have recently set a password not more than 7 days ago. You may try changing your password at a later date.',
		'change_password_same_old': 'Sorry, you cannot use your previous password.',
		'lost_password_sps_request_sent': 'A message shall be sent to you via SMS regarding your lost password request.',
		'lost_password_pending_request': "You already have a pending lost password request. An SMS shall be sent to you once processing of your request has been completed.",
		'session_control': "Your Wi-Fi account can only have 1 session at a time. To continue using Wi-Fi data connection, please disconnect your active Wi-Fi/3G session. To learn more of this error, please click here: <a href='/info/help'>#URL/info/help</a>.",
		'non_smart_msisdn': 'You have entered an invalid number. Please ensure that you enter a valid SMART Mobile Number.<br/><br/>(Mobile Number format: 09xxxxxxxxx)',
		'login_invalid_input': 'Please enter your Mobile Number and Password.',
		'msisdn_not_allowed': """Sorry, your account is not allowed to avail of this promo.<br/><br/>
			Available only for the following:<br/>
			Smart Bro Prepaid (with Unlisurf 200 subscription)<br/>
			Smart Bro Prepaid (with Always On 199, 299, 499 or 995 subscription)<br/>
			Smart Postpaid Unlimited Data Plans<br/>
			Smart Postpaid Data Lite Plans<br/>
			Smart Postpaid iPhone Plans<br/>"""
	}

	def connect(self):
		model_config = self.config['model_config']
		self.log.debug('Connecting to mongod..')
		try:
			self.connection = pymongo.Connection(model_config['mongod_ip'], int(model_config['mongod_port']))
			self.db = self.connection[model_config['database_name']]
			if model_config['authenticate']:
				if not self.db.authenticate(model_config['username'], model_config['password']):
					self.log.error('Network MongoDB authentication failed.')
					return False
					
			if 'vms' in self.config:
				self.vms_db = self.connection[self.config['vms']['database_name']]				
				if self.config['vms']['authenticate']:
					if not self.vms_db.authenticate(self.config['vms']['username'], self.config['vms']['password']):
						self.log.error('VMS MongoDB authentication failed.')
						return False
				self.vms_packages = {}
				for package in self.vms_db.packages.find(fields=['policy_id', 'credit_validity', 'name', 'usage_type', 'cap']):
					self.vms_packages[package['policy_id']] = package
				
			self.logins = self.db.logins
			self.session_infos = self.db.session_infos			
		except Exception as err:
			self.log.error('MongoDB connection error: %s', err)
			return False
		self.log.debug('Connected to MongoDB %s', self.connection)
		
		return True
		
	def save_login_time(self, subscriber_id):
		try:
			session_infos = self.session_infos
			session_info = session_infos.find_one({'_id': subscriber_id})
			if session_info is None:
				session_info = {
					'_id': subscriber_id,
					'login_time': datetime.datetime.now()
				}
				session_infos.insert(session_info)
			else:
				session_info['login_time'] = datetime.datetime.now()
				session_infos.save(session_info)
			
			self.logins.remove({'_id': subscriber_id})
		except Exception as err:
			self.log.error('MongoDB sess_info_login_time error: %s' % (err))
			if not hasattr(self, 'connection'):
				self.log.error('MongoDB Reconnecting..')
				self.connect()
			return False
			
		return True
		
	def get_session_age(self, subscriber_id):
		try:
			session_info = self.session_infos.find_one({'_id': subscriber_id})
			if session_info is not None:
				td = datetime.datetime.now() - session_info['login_time']
				return utils.timedelta_str(td)
		except Exception as err:
			if not hasattr(self, 'connection'):
				self.log.error('MongoDB Reconnecting..')
				self.connect()
			self.log.error('MongoDB sess_info_login_time error: %s' % (err))

		return ''
	
	def spiel(self, id):
		msg = self.spiels[id]
		if not request.is_jquery:
			msg = utils.strip_html(msg)
		return msg.replace('#URL', 'https://%s' % (request.source['portal_ip']))
	
#
# Network Actions
#
class Actions:
	#
	# Login Form
	#
	def login_form(self):
		if 'do' in request.args and request.args['do'] == 'captcha_img':
			if 'captcha' not in session:
				abort(503)			
			else:
				response = make_response(session['captcha'].image())
				response.headers.add('Content-Type', 'image/png')
				return response 
		
		if 'next' in request.args:
			next_page = request.args['next']
		else:
			next_page = utils.extract_nextpage(request, self.wide)
			
		session['next'] = next_page

		request.response.headers.add('X-Gateway-Session', '0')		
		request.response.data = render_template_string(request.templates['login'], templates=request.template_objects, partners=partners)
		return request.response
	
	#
	# Login Submit
	#
	def login_submit(self):
		username = str(request.form['principal']) if 'principal' in request.form else None
		password = str(request.form['credential']) if 'credential' in request.form else None
		partner = str(request.form['partner']) if 'partner' in request.form else None

		if username == None or password == None or partner == None:
			self.log.info('Missing login information (%s|%s|%s)', username, password, domain)
			return redirect(url_for('login_form'), headers={'X-Login-Successful': '0'})

		if username == "" or password == "":
			flash(self.model.spiel('login_invalid_input'), 'error')
			return redirect(url_for('login_form'), headers={'X-Login-Successful': '0'})

		if partner not in partners:
			flash('Invalid partner', 'error')
			return redirect(url_for('login_form'), headers={'X-Login-Successful': '0'})

		domain = partners[partner].domain

		subscriber_id = '%s@%s' % (username, domain)
		self.log.info('Login.start [%s]: password is ***', subscriber_id)

		# Check CAPTCHA		
		# MD5 Hash the password
		#password = utils.password_hash(password)		
		# Check username & password		
		# Check Lockout here		
		# Check Password	
		# Login OK
		
		#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
		# Portal Session is now Valid
		#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
		session['Subscriber-Id'] = subscriber_id
		#session['Profile-Set'] = aaa_user_profile_set
		#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
		# Portal Session is now Valid
		#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!		
			
		# Send account-logon CoA to ISG
		self.log.info('Sending logon %s:%s to WAG..', subscriber_id, password)
		logon_result, logon_message, logon_attrs = request.gateway_session.logon(subscriber_id, password, request.gateway_session_id)
		if not logon_result:
			session.destroy()
			if type(logon_message) == type(u''):
				self.log.error('Login.end system_error [%s]: WAG login CoANaK: %s', subscriber_id, logon_message)				
				if logon_message == 'Access denied, session limit exceeded':			
					flash(self.model.spiel('session_control'), 'error')
				else:
					flash(self.model.spiel('system_timeout'), 'error')
			else:
				self.log.error('Login.end system_error [%s]: WAG session login returned CoANaK', subscriber_id)
				flash(self.model.spiel('system_timeout'), 'error')

			return redirect(url_for('login_form'), headers={'X-Login-Successful': '0'})
			
		#!!!!!!!!!!!!!!!!!!!!!!!!!!!
		# GATEWAY SESSION NOW VALID
		#!!!!!!!!!!!!!!!!!!!!!!!!!!!
		session['Gateway-Session'] = True

#		self.model.save_login_time(session['Subscriber-Id'])
		self.log.info('Login.end ok [%s]', subscriber_id)
		
		request.response.headers.add('X-Login-Successful', '1')		
		request.response.data = render_template_string(request.templates['welcome'], templates=request.template_objects)		
		return request.response

	#
	# Status
	#
	def status(self):
		if 'do' in request.args and request.args['do'] == 'usage_chart':
			if 'usage' in session and 'account_type' in session and 'Used' in session['usage'][session['account_type']]:			
				p = PieChart([('Used', session['usage'][session['account_type']]['Used']), ('Free', session['usage'][session['account_type']]['Cap']-session['usage'][session['account_type']]['Used'])], 85)			
				response = make_response(p.draw())
				response.headers.add('Content-Type', 'image/png')
				return response 
			else:
				return abort(503)
		print 'status_session', session

		metering_ok = True
		metered = False

		# Usage History
		if 'sessacct' in self.config and 'Session-Start' in session:
			request.session_age = utils.timedelta_str(datetime.datetime.now() - session['Session-Start'])
		else:
			request.session_age = ''
#			request.session_age = self.model.get_session_age(session['Subscriber-Id'])
				
		request.response.headers.add('X-Gateway-Session', '1')
		request.response.data = render_template_string(request.templates['status'], templates=request.template_objects, sess=session, metered=metered, metering_ok=metering_ok, subscriber_ip=session['IP-Address'], subscriber_id=session['Subscriber-Id'])
		return request.response
	
	#
	# Logout
	#
	def logout(self, mesg):
		session.destroy()
		if mesg == "depleted":
			flash(self.model.spiel('quota_depleted'), 'error')
		else:
			flash(self.model.spiel('logout'), 'error')
		self.log.info('Logging off %s', request.gateway_session_id)
		request.gateway_session.logoff(request.gateway_session_id)
		
		self.log.info('Verifying logoff..')
		if 'sessacct' in self.config:
			time.sleep(2)
			print 'Checking for accounting stop..'
			for n in range(4):
				sessacct = self.model.getSessionByIP()
				print '  ', sessacct

				if not sessacct:
					break

				if sessacct['Acct-Status-Type'] == 'Stop':
					break
				time.sleep(1)
		else:
			time.sleep(2)
			for n in range(4):
				if not request.gateway_session.session_sync(request, session):
					break
				time.sleep(1)		
				
		session['Gateway-Session'] = False
		return redirect(url_for('login_form'), headers={'X-Logout-Successful': '1'})

	#
	# Info
	#
	def info(self, info_id):
		template_id = '__info__%s' % (info_id)
		if template_id in request.templates:
			request.response.data = render_template_string(request.templates[template_id], templates=request.template_objects)
			return request.response		
		else:
			return abort(404)