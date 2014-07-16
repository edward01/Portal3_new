### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### 
# Smart WiFi - Captive Portal
# ## ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ##
#
# Smart Phase 1 Network Module
#
# Valid session: if 'Subscriber-Id' in session 

from flask import url_for as flask_url_for, request, make_response, render_template, render_template_string, flash, abort, session, redirect
from captcha import captcha
from piechart import PieChart
import utils, time, datetime, pymongo, json, re, pymongo_safe

# endpoint with network path support
def url_for(endpoint):
	if type(request.view_args) == type({}) and 'path' in request.view_args:
		return '/%s%s' % (request.view_args['path'], flask_url_for(endpoint))
	return flask_url_for(endpoint)

# from config
def network_path_url_for(endpoint):
	try:
		url = '/%s%s' % (request.source['network']['url_path'], flask_url_for(endpoint))
	except:
		url = flask_url_for(endpoint)
	return url
	
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

	default_country_code = '63'
	allowed_msisdn_ranges = []
	
	def is_msisdn_allowed(self, msisdn):
		msisdn = int(msisdn)
		for allowed_msisdn_range in self.allowed_msisdn_ranges:
			if msisdn >= allowed_msisdn_range[0] and msisdn <= allowed_msisdn_range[1]:
				return True
		return False

	def connect(self):
		model_config = self.config['model_config']
		self.log.debug('(network_smart_wifi_ph1) Connecting to mongod..')

		connections = pymongo_safe.MongoHandler(model_config)
		#self.db = connections['portal'][model_config['portal']['name']]
		self.db = connections['portal_smart_wifi']['portal_smart_wifi']

		self.logins = self.db.logins
		self.session_infos = self.db.session_infos
		self.sps_requests = self.db.sps_requests
		self.confirmations = self.db.confirmations # SMS Throttling

		# Preload allowed min ranges
		#self.allowed_msisdn_ranges = []
		if 'allowed-min-ranges' in self.config and 'range' in self.config['allowed-min-ranges']:
			print 'min range', self.config['allowed-min-ranges']
			for min_range in self.config['allowed-min-ranges']['range']:
				print min_range
				if min_range.find(',') != -1:
					self.allowed_msisdn_ranges.append(tuple(map(int, min_range.split(','))))
		else:
			self.log.error('Warning! No allowed min ranges defined.')
			
		return True
	
	def getSessionByIP(self):
		try:
			ippadr = request.environ['REMOTE_ADDR']
			sessions = self.db[self.config['sessacct']['collection']]
			session = sessions.find_one({'Framed-IP-Address': ippadr}, sort=([('_timestamp', pymongo.DESCENDING)]))
			if session == None:
				return False
			return session
		except Exception as ex:
			self.log.error('getSessionByIP error: %s', ex)
		return False
	
	def sessacct_sync(self, session):
		print '  sessacct_sync', request.environ['REMOTE_ADDR']
		try:
			ippadr = request.environ['REMOTE_ADDR']
			sessions = self.db[self.config['sessacct']['collection']]
			sessacct = sessions.find_one({'Framed-IP-Address': ippadr, 'Acct-Status-Type': {'$in': ['Start', 'Alive'] }}, sort=([('_timestamp', pymongo.DESCENDING)]))
			print '  sessacct_data', sessacct
			if sessacct == None:
				return False

			if 'append-domain' in self.config['sessacct']:
				self.log.info('Appending domain %s to %s', self.config['sessacct']['append-domain'], sessacct['User-Name'])
				sessacct['User-Name'] = '%s@%s' % (sessacct['User-Name'], self.config['sessacct']['append-domain'])
			
			session['Subscriber-Id'] = sessacct['User-Name']
			session['IP-Address'] = sessacct['Framed-IP-Address']
			session['Gateway-Session'] = True
			if '_start_timestamp' in sessacct:
				session['Session-Start'] = sessacct['_start_timestamp']
			
			return True
		except Exception as ex:
			self.log.error('sessacct_sync error: %s', ex)
		return False
	
	# to be replaced with sessacct
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
	
	# to be replaced with sessacct
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

	def check_msisdn(self, msisdn):	
		if len(msisdn) == 0:
			return False, None, self.spiels['non_smart_msisdn']
		
		if not msisdn.isdigit():
			return False, None, self.spiels['non_smart_msisdn'] 
		
		if msisdn[0] == '0':
			msisdn = '%s%s' % (self.default_country_code, msisdn[1:])
		
		if len(msisdn) != 12:
			return False, None, self.spiels['non_smart_msisdn']
		
		if not self.is_msisdn_allowed(msisdn):
			self.log.info('MSISDN range not allowed: %s' % (msisdn))
			return False, None, self.spiels['msisdn_not_allowed']
		
		return True, msisdn, None

	############
	# Lockouts
	# Should we have a cron job to clean this up?
	def failed_login_attempt(self, subscriber_id):
		try:
			login = self.logins.find_one({'_id': subscriber_id})
			if login == None:
				login = {
					'_id': subscriber_id,
					'attempt': 1,
					'last_login': datetime.datetime.now(),
					'captcha': False,
					'lockout_warning': False,		
					'lockout': False
				}
				self.logins.insert(login)
			else:
				self.log.info('Last login state: %s', login)
				# Last login time reset hit
				td = datetime.datetime.now() - login['last_login']
				if ((td.microseconds + (td.seconds + td.days * 24 * 3600) * 10**6) / 10**6) > int(self.config['lockout']['reset']):
					login['attempt'] = 1
					login['captcha'] = False
					login['lockout'] = False
					login['lockout_warning'] = False
				else:
					login['attempt'] += 1
					
					if login['attempt'] >= int(self.config['lockout']['captcha_attempts']):
						login['captcha'] = True
	
					lockout_diff = int(self.config['lockout']['lockout_attempts']) - login['attempt']
	
					if lockout_diff == 1:
						login['lockout_warning'] = True
						
					if lockout_diff == 0:
						login['lockout'] = True					
					
			login['last_login'] = datetime.datetime.now()		
			self.logins.save(login)
			return login
		except Exception as err:
			self.log.error('MongoDB failed_login_attempt error: %s' % (err))
			if not hasattr(self, 'connection'):
				self.log.error('MongoDB Reconnecting..')
				self.connect()
			return False
	
	def is_locked_out(self, subscriber_id):
		try:
			login = self.logins.find_one({'_id': subscriber_id})
			if login != None:
				#print 'is_locked_out', login
				if 'last_login' not in login:
					return False
				td = datetime.datetime.now() - login['last_login']
				if ((td.microseconds + (td.seconds + td.days * 24 * 3600) * 10**6) / 10**6) > int(self.config['lockout']['reset']):
					return False
				
				if 'lockout' in login and login['lockout']:
					return True
			return False
		except Exception as err:
			self.log.error('MongoDB is_locked_out error: %s' % (err))
			if not hasattr(self, 'connection'):
				self.log.error('MongoDB Reconnecting..')
				self.connect()
			return False
	
	def spiel(self, id, code=None):
		msg = self.spiels[id]
		if code != None and True: # make this configurable
			msg = '%s (%s)' % (msg, code)

		if not request.is_jquery:
			msg = utils.strip_html(msg)
		return msg.replace('#URL', 'https://%s' % (request.source['portal_ip']))
		
	def get_confirmation(self, mobile_number, formtype):
		confirmation = self.confirmations.find_one({'mobile_number': mobile_number, 'formtype':formtype}, sort=([('timestamp', pymongo.DESCENDING)]))
		if confirmation:
			if 'finished' in confirmation:
				self.log.info('Confirmation record %s for %s already used.', confirmation['_id'], mobile_number)
				return False
		
			confirmation_td = utils.delta_totalseconds(datetime.datetime.now() - confirmation['timestamp'])
			if confirmation_td <= int(self.config['confirmations']['validity']):
				self.log.info('Confirmation record %s for %s (%s/%s seconds) is still valid.', confirmation['_id'], mobile_number, confirmation_td, self.config['confirmations']['validity'])
				return confirmation
			else:
				self.log.info('Confirmation record %s for %s (%s/%s seconds) is already expired.', confirmation['_id'], mobile_number, confirmation_td, self.config['confirmations']['validity'])
		else:
			self.log.info('There is no confirmation record for %s.', mobile_number)
			
		return False
	
	def tag_confirmation(self, _id):
		confirmation = self.confirmations.find_one({'_id': _id})
		if confirmation:
			confirmation['finished'] = datetime.datetime.now()
			self.confirmations.save(confirmation)
			return True
		return False

	def validate_password(self, passwd):
		if len(passwd) >= 8 and len(passwd) <= 16:
			if re.search('[a-zA-Z]+', passwd) and re.search('[0-9]+', passwd):    	
				return True
		return False  

	def before_request(self):
		request.url_for = url_for
	
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
			
		captcha_form = False
		if 'captcha_active' in session:
			captcha_form = True
			session['captcha'] = captcha(request.gateway_session_id)
			self.log.info('Captcha Validation: %s', session['captcha']._generate_words())
		
		session['next'] = next_page

		request.response.data = render_template_string(request.templates['login'], templates=request.template_objects, organizations=self.wide.organizations, captcha_form=captcha_form)
		return request.response


	#
	# HMAC Security
	#
	def sortedparameters(parameters):
		output = []
		for key in sorted(parameters.iterkeys()):
		    output.append("%s=%s" % (key, parameters[key]))
	
		return '?' + '&'.join(output)
		    
	def hmacdigest(method, resource, parameters, nonce, udid):
		concat = str('%s%s%s%s' % (method, resource, parameters, nonce)).lower()
		udid = str(udid)
		print 'CONCAT', concat, 'UDID', udid
		return hmac.new(udid, concat, hashlib.sha256).hexdigest()
	
	#
	# Login Submit
	#
	# OK Replace 0XXX -> 63XXX 
	# OK Lockout loophole: count username login attempts instead of counting global
	# OK Check credits before doing ISG account_logon
	#
	def login_submit(self):
#		username = str(request.form['principal']) if 'principal' in request.form else None
#		password = str(request.form['credential']) if 'credential' in request.form else None
		username = request.form.get('principal', None)
		password = request.form.get('credential', None)

		if 'domain' not in request.form:
			self.log.info('No domain submitted. Redirecting.')
			return redirect(url_for('login_form'))

		if 'domain' in request.form and str(request.form['domain']) not in self.wide.organizations:
			self.log.debug('Domain %s not allowed', str(request.form['domain']))
			return redirect(url_for('login_form'))
		
		if username == None or password == None:		
			self.log.info('Missing login information (%s|%s)', username, password)
			return redirect(url_for('login_form'))

		if username == "" or password == "":
			flash(self.model.spiel('login_invalid_input'), 'error')
			return redirect(url_for('login_form'))

		pusername = username
		domain = self.config['domain']
		msisdn_valid, username, msisdn_error_message = self.model.check_msisdn(username) 

		subscriber_id = '%s@%s' % (username, domain)
		self.log.info('Login.start [%s@%s]: password is ***', pusername, domain)

		if not msisdn_valid:
			self.log.info('Login.end user_error [%s]: Invalid MSISDN: %s', subscriber_id, msisdn_error_message)
			flash(msisdn_error_message)
			return redirect(url_for('login_form'))			
		
		# Check CAPTCHA
		if 'captcha_active' in session:
			if 'captcha' in request.form and 'captcha' in session:
				self.log.info('CAPTCHA entered: %s expected: %s', request.form['captcha'], session['captcha']._generate_words())
				if session['captcha'].verify(request.form['captcha']):
					del(session['captcha'])
				else:				
					self.log.info('Login.end user_error [%s]: CAPTCHA mismatch', subscriber_id)
					flash(self.model.spiel('incorrect_captcha'), 'error')
					return redirect(url_for('login_form'))							
			else:
				self.log.info('Login.end user_error [%s]: CAPTCHA mismatch', subscriber_id)
				flash(self.model.spiel('incorrect_captcha'), 'error')
				return redirect(url_for('login_form'))			
		
		# MD5 Hash the password
		password = utils.password_hash(password)
		
		# Check username & password
		self.log.info('Sending GetUser %s:%s', username, password)
		getuser = request.sdb.getUser(username, domain)		
		
		if getuser == False:
			self.log.error('Login.end system_error [%s]: SDB.getUser returned False', subscriber_id)
			flash(self.model.spiel('system_timeout', code='356a1'), 'error')
			return redirect(url_for('login_form'))			
			
		if 'error' in getuser['target']:
			if getuser['target']['error']['code'] == 'USR-00001':
				self.log.info('Login.end user_error [%s]: User does not exist', subscriber_id)
				flash(self.model.spiel('invalid_account'), 'error')				
			else:
				self.log.error('Login.end system_error [%s]: SDB.getUser result code unknown', subscriber_id)
				flash(self.model.spiel('system_timeout', code='da4b9'), 'error')
			return redirect(url_for('login_form'))
	
		try:
			aaa_user_status = getuser['target']['result']['user']['status']['value']
			aaa_user_password = getuser['target']['result']['user']['password']['value']
			aaa_user_profile_set = getuser['target']['result']['user']['profile-set']['name'] 
		except Exception as ex:
			self.log.error('Login.end system_error [%s]: Getuser parsing: %s', subscriber_id, getuser)
			flash(self.model.spiel('system_timeout', code='77de6'), 'error')
			return redirect(url_for('login_form'))
		
		# Check Lockout here
		if self.model.is_locked_out(subscriber_id):
			self.log.info('Login.end user_error [%s]: User locked out', subscriber_id)
			session.destroy()
			flash(self.model.spiel('lockout'), 'error')
			return redirect(url_for('login_form'))			
		
		if aaa_user_status == 'suspended':
			self.log.info('Login.end user_error [%s]: User suspended', subscriber_id)
			flash(self.model.spiel('account_suspended'), 'error')
			return redirect(url_for('login_form'))

		if aaa_user_status == 'pending':
			self.log.info('Login.end user_error [%s]: User suspended', subscriber_id)
			flash(self.model.spiel('invalid_account'), 'error')
			return redirect(url_for('login_form'))
		
		# Check Password
		if aaa_user_password != password:
			# FAILED ATTEMPT
			login_state = self.model.failed_login_attempt(subscriber_id)
			if login_state == False:
				flash(self.model.spiel('incorrect_credentials'), 'error')
			else:			
				if login_state['captcha']:
					session['captcha_active'] = True
				elif not login_state['captcha'] and 'captcha_active' in session:
					del(session['captcha_active'])
	
				if login_state['lockout']:
					session.destroy()
					flash(self.model.spiel('lockout'), 'error')
				elif login_state['lockout_warning']:					
					flash(self.model.spiel('lockout_warning'), 'error')
				else:
					flash(self.model.spiel('incorrect_credentials'), 'error')

			self.log.info('Login.end user_error [%s]: Incorrect password', subscriber_id)
			return redirect(url_for('login_form'))
	
		# Login OK
		
		#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
		# Portal Session is now Valid
		#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
		session['Subscriber-Id'] = subscriber_id
		session['Profile-Set'] = aaa_user_profile_set
		#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
		# Portal Session is now Valid
		#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!		
			
		#if organization['metered']:
		if aaa_user_profile_set in ('3G_UPS', 'Default Postpaid'):
			# Iterate over the session rights
			if not request.bpc.process_session_rights(session):
				session.destroy()
				self.log.error('Login.end system_error [%s]: BPC session rights processing returned False', subscriber_id)
				flash(self.model.spiel('system_timeout', code='1b645'), 'error')
				return redirect(url_for('login_form'))		

			# TTCs		
			#ttc_list = request.bpc.GetTTCList(subscriber_id)
			#self.log.debug('TTC LIST: %s', session['ttc_list'].keys())
		
			# Check if the account is used up
			#if 'Quota_Depleted' in session['ttc_list']:
			#	self.log.info('Login.end user_error [%s]: TTC Quota_Depleted present', subscriber_id)
			#	session.destroy()
			#	flash(self.model.spiel('quota_depleted2'), 'error')
			#	return redirect(url_for('login_form'))

			if session['rights'] == {}:
				self.log.info('Login.end user_error [%s]: Session rights empty', subscriber_id)
				session.destroy()
				flash(self.model.spiel('quota_depleted2'), 'error')
				return redirect(url_for('login_form'))		
					
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
					flash(self.model.spiel('system_timeout', code='902ba'), 'error')
			else:
				self.log.error('Login.end system_error [%s]: WAG session login returned CoANaK', subscriber_id)
				flash(self.model.spiel('system_timeout', code='fe5db'), 'error')

			return redirect(url_for('login_form'))

		#!!!!!!!!!!!!!!!!!!!!!!!!!!!
		# GATEWAY SESSION NOW VALID
		#!!!!!!!!!!!!!!!!!!!!!!!!!!!
		session['Gateway-Session'] = True
#		session['IP-Address'] = logon_attrs['Cisco-Account-Info'][0]

		self.model.save_login_time(session['Subscriber-Id'])
		self.log.info('Login.end ok [%s]', subscriber_id)
		
		request.response.data = render_template_string(request.templates['welcome'], templates=request.template_objects)		
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
			print 'XXXXX'
			time.sleep(2)
			for n in range(4):
				if not request.gateway_session.session_sync(request, session):
					break
				time.sleep(1)
				
		return redirect(url_for('login_form'))
	
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
		if 'Profile-Set' not in session:
			session['Profile-Set'] = False
			self.log.debug('Sending GetUser %s', request.username)
			getuser = request.sdb.getUser(request.username, request.domain)		
			if getuser != False:				
				if 'error' in getuser['target']:
					self.log.error('status SDB.getuser_error %s', getuser['target']['error'])
				else:
					try:
						session['Profile-Set'] = getuser['target']['result']['user']['profile-set']['name'] 
					except:		
						self.log.error('status SDB.getUser invalid response')
#						session['Profile-Set'] = False
						pass
			else:
				self.log.error('status SDB.getUser returned False')
				
#		if request.organization['metered']:
#		if metering_ok:
		if session['Profile-Set'] == '3G_UPS': #REFACTOR THIS
			metered = True
			if not request.bpc.process_session_rights(session): #, force=True):
				metering_ok = False		
			else:
				if session['account_type'] is None:
					self.log.debug('From Status, User has no active session rights. Logging off.')
					request.response.data = render_template_string(self.wide.generic_redirect_html, delay=2, target_url='%s://%s:%s/logoff/depleted' % (self.wide.proto, self.wide.portal_host, self.wide.portal_port))
					return request.response

		# Usage History
		if 'sessacct' in self.config and 'Session-Start' in session:
			request.session_age = utils.timedelta_str(datetime.datetime.now() - session['Session-Start'])
		else:
			request.session_age = self.model.get_session_age(session['Subscriber-Id'])
				
		request.response.data = render_template_string(request.templates['status'], templates=request.template_objects, sess=session, metered=metered, metering_ok=metering_ok, subscriber_ip=session['IP-Address'], subscriber_id=session['Subscriber-Id'])
		return request.response

	#
	# Confirmation Forms (Registration and Lost Password)
	#
	def confirmation_form(self, formtype):	
		if 'do' in request.args and request.args['do'] == 'resendactivationcode':
			if 'confirmation_mobile_number' in session:
				previous_confirmation = self.model.get_confirmation(session['confirmation_mobile_number'], formtype)
				if previous_confirmation:
					sms_string = self.model.spiel('activation_code') % (previous_confirmation['code'])
					self.log.debug('SMS: Resending "%s" to %s',  sms_string, session['confirmation_mobile_number'])
					if not self.wide.sms.send(session['confirmation_mobile_number'], sms_string):
						self.log.error('smsc.send returned False')
						flash(self.model.spiel('system_timeout', code='9e6a5'), 'error')
						return redirect(url_for('login_form'))
					return redirect(url_for('%s_form' % (formtype)) + '?phase=2')
					
			return redirect(url_for('%s_form' % (formtype)) + '?phase=1')		

		phase = int(request.args['phase']) if 'phase' in request.args else 1
		self.log.info('Confirmation form phase %s type %s', phase, formtype)

#		if phase != 1 and 'confirmation_form_type' in session and session['confirmation_form_type'] != formtype:
#			self.log.debug('Jumping between lost_password and register?. Destroying session.')
#			session.destroy()
#			return redirect(url_for('login_form'))
			
		if phase == 1:
			session['confirmation_form_type'] = formtype
			request.response.data = render_template_string(request.templates['%s1' % (formtype)], templates=request.template_objects)
		elif phase == 2 and 'confirmation_mobile_number' in session:
			request.response.data = render_template_string(request.templates['%s2' % (formtype)], templates=request.template_objects)
		elif phase == 3 and 'confirmation_activation_ok' in session:
			request.response.data = render_template_string(request.templates['%s3' % (formtype)], templates=request.template_objects)
		else:
			return redirect(url_for('%s_form' % (formtype)) + '?phase=1')		
		return request.response		

	#
	# Confirmation Forms Submit (Registration and Lost Password)
	#
	# db.confirmations: *optional?
	# _id				autogenerated
	# mobile_number
	# timestamp			datetime.datetime.now()
	# formtype			register|lost_password
	# phase				1|2|3
	# code				autogenerated
	#*sms_sent			True|False
	#
	def confirmation_submit(self, formtype):
		phase = int(request.form['phase']) if 'phase' in request.form else 1
		self.log.info('Confirmation submit phase %s type %s', phase, formtype)
		print session
		if len(session) == 0:
			self.log.debug('Session is empty. Ejecting.')
			return redirect(url_for('login_form'))

		# Phase 1: Mobile Number Entry
		if phase == 1:
			if 'confirmation_activation_ok' in session:
				del(session['confirmation_activation_ok']) 
#			if 'confirmation_activation_code' in session:
#				del(session['confirmation_activation_code']) 
#			if 'confirmation_mobile_number' in session:
#				del(session['confirmation_mobile_number']) 

			# Valid MSISDN Check
			domain = self.config['domain']

			msisdn_valid, mobile_number, msisdn_error_message = self.model.check_msisdn(request.form['mobile_number'])
			if not msisdn_valid:
				self.log.info('Invalid MSISDN %s: %s', request.form['mobile_number'], msisdn_error_message)
				session.destroy()
				flash(msisdn_error_message)
				return redirect(url_for('%s_form' % (formtype)))

			getuser = request.sdb.getUser(mobile_number, domain)
			if getuser == False:
				self.log.error('SDB.getUser returned False')
				flash(self.model.spiel('system_timeout', code='7b520'), 'error')
				return redirect(url_for('login_form'))			
			
			previous_confirmation = self.model.get_confirmation(mobile_number, formtype)
			if previous_confirmation:
				session['confirmation_mobile_number'] = mobile_number
				if request.entrypoint_redirected:
					return redirect(network_path_url_for('%s_form' % (formtype)) + '?phase=2')
				else:
					return redirect(url_for('%s_form' % (formtype)) + '?phase=2')				
			
			# User does not exist
			if 'error' in getuser['target']:
				if formtype == 'register':
					if getuser['target']['error']['code'] == 'USR-00001':
						# send confirmation
						pass
					else:
						self.log.error('Get user_error Code %s' % (getuser['target']['error']['code']))
						return redirect(url_for('login_form'))												
				elif formtype == 'lost_password':
					self.log.info('Lost Password: account %s does not exist.', mobile_number)
					session.destroy()
					flash(self.model.spiel('invalid_account'), 'error')				
					return redirect(url_for('%s_form' % (formtype)))
			# User Exists
			else:
				if formtype == 'register':
					try:
						aaa_user_status = getuser['target']['result']['user']['status']['value']
					except Exception as ex:
						self.log.error('Register error: %s@%s Getuser parsing: %s', username, domain, getuser)
						flash(self.model.spiel('system_timeout', code='472b0'), 'error')
						return redirect(url_for('%s_form' % (formtype)))

					if aaa_user_status == 'active':
						session.destroy()
						self.log.info('Register: account %s already exists.', mobile_number)
						flash(self.model.spiel('account_exists'), 'error')			
						return redirect(url_for('login_form'))
					else:
						# send confirmation
						pass
												
				elif formtype == 'lost_password':
					# CHECK sps_requests for existing entry
					if self.model.sps_requests.find_one({'msisdn': mobile_number, 'sms_sent': False, 'type': 'CHPWD'}, sort=([('request_datetime', pymongo.DESCENDING)])) != None:
						session.destroy()
						flash(self.model.spiel('change_password_pending_request'))
						return redirect(url_for('%s_form' % (formtype)))						

					session['confirmation_mobile_number'] = mobile_number
					if not self.send_activation_code(mobile_number, formtype):
						self.log.error('smsc.send returned False')
						flash(self.model.spiel('system_timeout', code='9e6a5'), 'error')
						return redirect(url_for('login_form'))									

					if request.entrypoint_redirected:
						return redirect(network_path_url_for('%s_form' % (formtype)) + '?phase=2')
					else:
						return redirect(url_for('%s_form' % (formtype)) + '?phase=2')				
						
			# !!!
			# send confirmation
			# CHECK sps_requests for existing entry
			if self.model.sps_requests.find_one({'msisdn': mobile_number, 'sms_sent': False, 'type': 'NWCON'}, sort=([('request_datetime', pymongo.DESCENDING)])) != None:
				self.log.info('registration pending for %s', mobile_number)
				session.destroy()
				flash(self.model.spiel('registration_pending_request'))
				return redirect(url_for('%s_form' % (formtype)))						
			
			session['confirmation_mobile_number'] = mobile_number
			if not self.send_activation_code(mobile_number, formtype):
				self.log.error('smsc.send returned False')
				flash(self.model.spiel('system_timeout', code='9e6a5'), 'error')
				return redirect(url_for('login_form'))
													
			if request.entrypoint_redirected:
				return redirect(network_path_url_for('%s_form' % (formtype)) + '?phase=2')
			else:
				return redirect(url_for('%s_form' % (formtype)) + '?phase=2')				

			
		# Phase 2: Activation Code Entry
		elif phase == 2 and 'confirmation_mobile_number' in session:
			submitted_activation_code = request.form['activation_code'] if 'activation_code' in request.form else ''
			
			current_confirmation = self.model.get_confirmation(session['confirmation_mobile_number'], formtype)
			if not current_confirmation:
				return redirect(url_for('%s_form' % (formtype)) + '?phase=1')
			current_activation_code = current_confirmation['code']
			
			self.log.debug('Compare [%s]=[%s]', submitted_activation_code, current_activation_code)
			if submitted_activation_code == current_activation_code:
				self.log.debug('Confirmation code ok.')
				session['confirmation_activation_ok'] = True
				session['confirmation_id'] = current_confirmation['_id']
				return redirect(url_for('%s_form' % (formtype)) + '?phase=3')				
			else:
				self.log.debug('Confirmation code incorrect.')
				flash(self.model.spiel('incorrect_activation_code'), 'error')			
				return redirect(url_for('%s_form' % (formtype)) + '?phase=2')
		
		# Phase 3: Password entry
		elif phase == 3 and 'confirmation_activation_ok' in session:
			if 'password1' not in request.form or 'password2' not in request.form:
				self.log.debug('Password1 and Password2 is not present on the submitted data.')
				return redirect(url_for('%s_form' % (formtype)) + '?phase=3')			

			if request.form['password1'] != request.form['password2']:
				self.log.debug('Password confirmation does not match.')
				flash(self.model.spiel('password_match_error'), 'error')			
				return redirect(url_for('%s_form' % (formtype)) + '?phase=3')			
			
			submitted_password = request.form['password1']
			if not self.model.validate_password(submitted_password):
				self.log.debug('Invalid Password')
				flash(self.model.spiel('invalid_password'), 'error')			
				return redirect(url_for('%s_form' % (formtype)) + '?phase=3')			
			
			# Hash the password
			submitted_password = utils.password_hash(submitted_password)
			
			## Check if the user exists
			mobile_number = session['confirmation_mobile_number']
			domain = self.config['domain']
			getuser = request.sdb.getUser(mobile_number, domain)
			if getuser == False:
				self.log.error('SDB.getUser returned False')
				flash(self.model.spiel('system_timeout', code='91032'), 'error')
				return redirect(url_for('login_form'))			

			# User doesnt exist
			if 'error' in getuser['target']:
				if getuser['target']['error']['code'] == 'USR-00001':
					if formtype == 'register':
						pass # Go SPS	
					elif formtype == 'lost_password':
						self.log.error('Lost Password: SDB Account does not exist.')
						flash(self.model.spiel('invalid_account'), 'error')			
						return redirect(url_for('login_form'))			
				else:
					self.log.error('SDB Error: %s', getuser['target']['error']['code'])
					return redirect(url_for('login_form'))			
				
			# User exists
			else:
				if formtype == 'register':
					try:
						aaa_user_status = getuser['target']['result']['user']['status']['value']
					except Exception as ex:
						self.log.error('Register error: %s@%s Getuser parsing: %s', username, domain, getuser)
						flash(self.model.spiel('system_timeout', code='472b0'), 'error')
						return redirect(url_for('%s_form' % (formtype)))

					if aaa_user_status == 'active':
						self.log.error('Register: SDB Account exists.')
						flash(self.model.spiel('account_exists'), 'error')			
						return redirect(url_for('login_form'))
					#else Go SPS!
					
				elif formtype == 'lost_password':
					subscriber_id = '%s@%s' % (mobile_number, domain)					
					self.log.info('Lost Password: sending to SPS %s:%s now.', subscriber_id, submitted_password)
					if request.sps.changePassword(mobile_number, submitted_password, self.model, subtype='LOST'):
						message = self.model.spiel('change_password_sps_request_sent')
						self.model.tag_confirmation(session['confirmation_id'])
					else:
						self.log.error('SPS.changePassword returned False')
						message = self.model.spiel('system_timeout', code='12c6f')					
					flash(message)
					return redirect(url_for('login_form'))			
			
			# !!!
			# Registration SPS
			subscriber_id = '%s@%s' % (mobile_number, domain)						
			self.log.info('Register: sending to SPS %s:%s now.', subscriber_id, submitted_password)
			if request.sps.createAccount(mobile_number, submitted_password, self.model):
				message = self.model.spiel('registration_sps_request_sent')
				self.model.tag_confirmation(session['confirmation_id'])
			else:
				self.log.error('SPS.createAccount returned False')
				message = self.model.spiel('system_timeout', code='d435a')
			flash(message)
			return redirect(url_for('login_form'))									
								
		else:
			return redirect(url_for('%s_form' % (formtype)) + '?phase=1')
		

	#
	# Send Activation Code
	#
	def send_activation_code(self, mobile_number, formtype):
		activation_code = utils.nicepass()
		#sess2db
		#session['confirmation_activation_code'] = activation_code
		self.model.confirmations.insert({
			'mobile_number': mobile_number,
			'timestamp': datetime.datetime.now(),
			'formtype': formtype,
			'code': activation_code
		})

		sms_string = self.model.spiel('activation_code') % (activation_code)
		self.log.debug('SMS: Sending "%s" to %s',  sms_string, mobile_number)
		return self.wide.sms.send(mobile_number, sms_string)
		
	#
	# Registration Form
	#
	def register_form(self):
		return self.confirmation_form('register')

	#
	# Registration Submit
	#
	def register_submit(self):
		return self.confirmation_submit('register')

	#
	# Lost Password Form
	#
	def lost_password_form(self):
		return self.confirmation_form('lost_password')
		
	#	
	# Lost Password Submit
	#	
	def lost_password_submit(self):
		return self.confirmation_submit('lost_password')
	
	#
	# Change Password Form
	#
	def change_password_form(self):
		request.response.data = render_template_string(request.templates['change_password'], templates=request.template_objects)
		return request.response
		
	#
	# Change Password Submit
	#
	def change_password_submit(self):
		subscriber_id = session['Subscriber-Id']
		username = subscriber_id.split('@')[0]
		domain = subscriber_id.split('@')[1]
		old_password = str(request.form['old_password'])
		new_password = str(request.form['new_password'])
		confirm_password = str(request.form['confirm_password'])
		#print username, old_password, new_password, confirm_password
		
		redirect_to = url_for('status_page')
		if '_np' in request.form:
			redirect_to = url_for('chpasswd_form')
			
		if domain != self.config['domain']:
			return redirect(url_for('status_page'))

		if self.model.sps_requests.find_one({'msisdn': username, 'sms_sent': False, 'type': 'CHPWD'}, sort=([('request_datetime', pymongo.DESCENDING)])) != None:
			flash(self.model.spiel('change_password_pending_request'))
			return redirect(url_for('status_page'))

		last_password_change = self.model.sps_requests.find_one({'msisdn': username, 'sms_sent': True, 'type': 'CHPWD', 'subtype': 'CHANGE'}, sort=([('request_datetime', pymongo.DESCENDING)]))
		if last_password_change != None:
			if 'request_datetime' in last_password_change:			
				td = datetime.datetime.now() - last_password_change['request_datetime']
				last_password_change_delta = utils.delta_totalseconds(td) #(td.microseconds + (td.seconds + td.days * 24 * 3600) * 10**6) / 10**6 #2.6/2.7 safe
				
				allowed_interval_seconds = 259200 # default is 3 days
				try:
					allowed_interval_seconds = int(self.config['passwords']['allowed_change_interval_seconds'])
				except:
					pass
				
				self.log.debug('ChangePassword for sub %s, allowed interval is %s, delta is %s', subscriber_id, allowed_interval_seconds, last_password_change_delta)
				if allowed_interval_seconds > last_password_change_delta:
					flash(self.model.spiel('change_password_interval_denied'), 'error')
					return redirect(url_for('status_page'))
		
		old_password_md5 = utils.password_hash(old_password)

		# Check Current Password
		self.log.debug('Sending GetUser %s:%s', username, old_password)
		getuser = request.sdb.getUser(username, domain)		
		if getuser == False:
			self.log.error('SDB.getUser returned False')
			flash(self.model.spiel('system_timeout', code='4d134'), 'error')
			return redirect(redirect_to)
			
		if 'error' in getuser['target']:
			self.log.error('SDB.getUser returned invalid contents')
			flash(self.model.spiel('system_timeout', code='f6e11'), 'error')
			return redirect(redirect_to)
	
		try:
			aaa_user_status = getuser['target']['result']['user']['status']['value']
			aaa_user_password = getuser['target']['result']['user']['password']['value']
		except Exception as ex:
			self.log.error('ChangePassword error: %s@%s Getuser parsing: %s', username, domain, getuser)
			flash(self.model.spiel('system_timeout', code='88730'), 'error')
			return redirect(redirect_to)
		
		# Check Old Password
		if aaa_user_password != old_password_md5:
			self.log.info('Change Password: Incorrect current password')		
			flash(self.model.spiel('incorrect_old_password'), 'error')	
			return redirect(redirect_to)

		if not self.model.validate_password(new_password):
			self.log.info('Change Password: Invalid new password')		
			flash(self.model.spiel('invalid_password'), 'error')			
			return redirect(redirect_to)
			
		if new_password != confirm_password:
			self.log.info('Change Password: Password confirmation does not match')		
			flash(self.model.spiel('password_match_error'), 'error')			
			return redirect(redirect_to)
			
		if old_password == new_password:
			self.log.info('Change Password: Invalid new password (same as the old one)')		
			flash(self.model.spiel('change_password_same_old'), 'error')			
			return redirect(redirect_to)

		new_password_md5 = utils.password_hash(new_password)

		subscriber_id = '%s@%s' % (username, domain)					
		self.log.info('Lost Password: sending to SPS %s:%s now.', subscriber_id, new_password_md5)
		if request.sps.changePassword(username, new_password_md5, self.model, subtype='CHANGE'):
			message = self.model.spiel('change_password_sps_request_sent')
		else:
			self.log.error('SPS.changePassword returned False')
			message = self.model.spiel('system_timeout', code='12c6f')
		flash(message)
		return redirect(url_for('status_page'))

	def zones(self):
		zone_result = []
		if request.method == 'GET' and 'location' in request.args and request.args['location'] in ('NMM', 'SMM', 'NL', 'CL', 'SL', 'VS', 'MD'):
			print {'zone_groups': {'$in': request.source['zone_groups_oid']}}
			for zone in self.wide.zones.find({'group_id': {'$in': request.source['zone_groups_oid'] }, 'area': request.args['location'] }, fields=['name', 'address']):
				zone_result.append(zone)
		
		if request.method == 'POST' and 'do' in request.args and request.args['do'] == 'search':
			query = re.compile('%s' % (str(request.form['query'])),re.IGNORECASE)
			for zone in self.wide.zones.find({'group_id': {'$in': request.source['zone_groups_oid'] }, '$or': [{'name': query}, {'address': query}] }, fields=['name', 'address']):
				zone_result.append(zone)
				print zone

		request.response.data = render_template_string(request.templates['zones'], templates=request.template_objects, zones_result=zone_result)
		return request.response
				

	def info(self, info_id):
		template_id = '__info__%s' % (info_id)
		if template_id in request.templates:
			request.response.data = render_template_string(request.templates[template_id], templates=request.template_objects)
			return request.response		
		else:
			return abort(404)
