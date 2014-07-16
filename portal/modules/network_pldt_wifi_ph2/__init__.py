###############################################################################
# PLDT WiFi - Captive Portal
###############################################################################
# Network Module
#

import utils
import time
import datetime
import re
import pymongo_safe
from flask import url_for as flask_url_for, request, make_response, render_template_string, flash, redirect, abort, session
from captcha import captcha
from piechart import PieChart
from bson.objectid import ObjectId

postpaid_check = re.compile('.+@postpaid.wifi.pldt.com.ph')

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

class switch(object):
    def __init__(self, value):
        self.value = value
        self.fall = False

    def __iter__(self):
        """Return the match method once, then stop"""
        yield self.match
        raise StopIteration
    
    def match(self, *args):
        """Indicate whether or not to enter a case suite"""
        if self.fall or not args:
            return True
        elif self.value in args: # changed for v1.5, see below
            self.fall = True
            return True
        else:
            return False

class dummy:
	pass

#
# Network Data Model
#
class Model:

	re_email = re.compile("^.+\\@(\\[?)[a-zA-Z0-9\\-\\.]+\\.([a-zA-Z]{2,3}|[0-9]{1,3})(\\]?)$")
	spiels = {
		'quota_depleted': "Your subscription has expired/has been fully consumed.",
		'account_suspended': "Sorry, your account is suspended.",
		'incorrect_credentials': "Invalid username or password. Please try again, or if you don't have a WiFi account yet, click <a href='/register'>#URL/register</a>.",
		'system_timeout': "Sorry, the system is taking longer to respond. Please try again.",
		'incorrect_captcha': "Incorrect security validation.",
		'invalid_account': "Sorry, you don't have a PLDT Wi-Fi account yet, Please register here.",		
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
		'login_invalid_input': 'Please enter your Mobile Number and Password.',
		'incorrect_security_answer': 'Incorrect security answer.',
		'invalid_email_address': 'Invalid email address.'
	}

	def connect(self):
		model_config = self.config['model_config']
		self.log.debug('Connecting to mongod..')

		connections = pymongo_safe.MongoHandler(model_config)
		self.db = connections['portal_pldt_wifi']['portal_pldt_wifi']
		self.vms_db = connections['vms'][model_config['vms']['name']]

		# Preload security questions
		self.security_questions = False
		if 'kenan' in self.config['gateway']:
			tmp_rq = dummy()
			tmp_rq.kenan = self.config['gateway']['kenan']
			tmp_rq.kenan.failover(tmp_rq)
			self.security_questions = tmp_rq.kenan.GetSecurityQuestions()

		return True
	
	def save_login_time(self, subscriber_id):
		try:
			session_infos = self.db.session_infos
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
			
			self.db.logins.remove({'_id': subscriber_id})
		except Exception as err:
			self.log.error('MongoDB sess_info_login_time error: %s' % (err))
			return False
			
		return True
		
	def get_session_age(self, subscriber_id):
		try:
			session_info = self.db.session_infos.find_one({'_id': subscriber_id})
			if session_info is not None:
				td = datetime.datetime.now() - session_info['login_time']
				return utils.timedelta_str(td)
		except Exception as err:
			self.log.error('MongoDB sess_info_login_time error: %s' % (err))

		return ''

	def vms_get_user(self, username, password):
		user = self.vms_db.batch_users.find_one({'username': username})		
#		plaintext_password = aes.decryptData(vms_cipher_key, user['password'])
#		if user != None and password == plaintext_password:
#			user['password'] = plaintext_password
#			return user
		if user is not None and utils.check_hash(password, user['hash_password']):
			return user
		return False

#	def vms_get_package(self, ttc_desc):
#		try:
#			return self.vms_db.packages.find_one({'policy_id': ttc_desc}, fields=['policy_id', 'credit_validity', 'name', 'usage_type', 'cap'])
#		except Exception as err:
#			self.log.error('MongoDB vms_get_package error: %s' % (err))
#		return False

	def vms_get_batch(self, batch_id):
		return self.vms_db.batches.find_one({'_id':batch_id})

	def vms_get_package(self, package_id):
		return self.vms_db.packages.find_one({'_id':ObjectId(package_id)})

	def vms_tag_activated(self, username):
		for n in range(3):
			try:
				vms_user = self.vms_db.batch_users.find_one({'username': username})
				vms_user['activated_datetime'] = datetime.datetime.now()
				vms_user['last_accessed_datetime'] = datetime.datetime.now()
				self.vms_db.batch_users.save(vms_user)
				return True
			except Exception as err:
				self.log.error('MongoDB vms_tag_activated error: %s' % (err))
		return False

	def vms_tag_last_accessed(self, username):
		for n in range(3):
			try:
				vms_user = self.vms_db.batch_users.find_one({'username': username})
				vms_user['last_accessed_datetime'] = datetime.datetime.now()
				self.vms_db.batch_users.save(vms_user)
				return True
			except Exception as err:
				self.log.error('MongoDB vms_tag_activated error: %s' % (err))
		return False

	def spiel(self, id, code=None):
		msg = self.spiels[id]
		if code != None and True: # make this configurable
			msg = '%s (%s)' % (msg, code)

		if not request.is_jquery:
			msg = utils.strip_html(msg)
		return msg.replace('#URL', 'https://%s' % (request.source['portal_ip']))
	
	def check_email_address(self, email):
		if self.re_email.match(email):
			return True
		return False

	def validate_password(self, passwd):
		if len(passwd) >= 8 and len(passwd) <= 16:
			if re.search('[a-zA-Z]+', passwd) and re.search('[0-9]+', passwd):    	
				return True
		return False  

	def before_request(self):
		request.url_for = url_for
	
	def get_user_info_from_session(self):
		if 'Subscriber-Id' not in session:
			return False
			
		try:
			user_id, domain = session['Subscriber-Id'].split('@')
		except:
			return False
	
		return {
			'user_id': user_id.replace(':', '@'),
			'aaa_user_id': user_id,
			'domain': domain,
			'subscriber_id': session['Subscriber-Id']
		}
	
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
		
		if 'sq' in request.args:
			if not self.model.security_questions:
				self.model.security_questions = request.kenan.GetSecurityQuestions()
			
			print 'SEC Qs', self.model.security_questions
			
			request.response.data = render_template_string(request.templates['security_question_redirection'], security_questions=self.model.security_questions, templates=request.template_objects)
			return request.response	
		
		if 'next' in request.args:
			next_page = request.args['next']
		else:
			next_page = utils.extract_nextpage(request, self.wide)
			
		captcha_form = False
		if 'captcha_active' in session:
			captcha_form = True
			session['captcha'] = captcha(request.cookies['sessid'])
			self.log.info('Captcha Validation: %s', session['captcha']._generate_words())
		
		session['next'] = next_page

		request.response.data = render_template_string(request.templates['login'], templates=request.template_objects, organizations=self.wide.organizations, captcha_form=captcha_form)
		return request.response
	
	#
	# Login Submit
	#
	# OK Replace 0XXX -> 63XXX 
	# OK Lockout loophole: count username login attempts instead of counting global
	# OK Check credits before doing ISG account_logon
	#
	def login_submit(self):
		if 'sq' in request.args and 'force_update_sq' in session:
			if 'sq_question' not in request.form or 'sq_answer' not in request.form:
				return abort(403)

			user = self.model.get_user_info_from_session()
			if not user:
				return abort(403)
		
			update_sq = request.kenan.UpdateUserSecurityQuestion(user['user_id'], request.form['sq_question'], request.form['sq_answer'])
			if type(update_sq) != type(u''):
				self.log.error('Security question update failed. Connection timed out.')
				flash(self.model.spiel('system_timeout', code='f1abd'), 'error')
				return redirect('/pldt/auth?sq')
							
			update_sq = int(update_sq)
			
			if update_sq == 0:
				self.log.info('Security question update successful!')
				del(session['force_update_sq'])
				return self._do_account_logon(session['Subscriber-Id'], session['Password'])
			else:
				self.log.error('Security question update failed. Error code %s returned.', update_sq)
				flash(self.model.spiel('system_timeout', code='1574b'), 'error')
				return redirect('/pldt/auth?sq')
		
		# normal login starts here			
		#username = str(request.form['principal']) if 'principal' in request.form else None
		#password = str(request.form['credential']) if 'credential' in request.form else None		
		username = request.form.get('principal', None)
		password = request.form.get('credential', None)
		#domain = request.form.get('domain', None)
		#print request.args, request.form, request.headers
		if username == None or password == None: #or paytype == None:
			self.log.info('Missing login information (%s|%s)', username, password)
			return redirect(url_for('login_form'))

		paytype = 'postpaid'
		if username.find('@') == -1:
			username = username.upper()
			password = password.upper()
			paytype = 'prepaid'
			domain = self.config['prepaid_domain']

		if paytype == 'postpaid':
			username = username.lower()
			orig_username = username
			username = username.replace('@', ':')
			domain = self.config['postpaid_domain']
			
		if username == "" or password == "":
			flash(self.model.spiel('login_invalid_input'), 'error')
			return redirect(url_for('login_form'))

		subscriber_id = '%s@%s' % (username, domain)
		self.log.info('Login.start [%s]: password is ***', subscriber_id)

		#
		# Voucher System		
		if paytype == 'prepaid':
			user = self.model.vms_get_user(username, password)			
			if user == False:
				self.log.info('Login.end user_error [%s]: User does not exist/incorrect password', subscriber_id)
				flash(self.model.spiel('invalid_account'), 'error')
				return redirect(url_for('login_form'))

			# Check if initial login
			if 'activated_datetime' not in user:									
				batch = self.model.vms_get_batch(user['batch_id'])
				if batch == None:
					self.log.info('Login.end system_error [%s]: Batch does not exist', subscriber_id)
					flash(self.model.spiel('system_timeout', code='bc33e'), 'error')
					return redirect(url_for('login_form'))
					
				package = self.model.vms_get_package(batch['package'])
				if package == None:
					self.log.info('Login.end system_error [%s]: Package does not exist', subscriber_id)
					flash(self.model.spiel('system_timeout', code='0a57c'), 'error')
					return redirect(url_for('login_form'))
				
				# Provisioning Stages
				for case in switch(user['stage']):
					#~ STAGE 1. ADDUSER	
					if case(1):
						self.log.info('Creating SDB user %s', subscriber_id)
						adduser = request.sdb.vmsAddUser(user['username'], user['username'], user['hash_password'], batch['domain'], batch['organization_qualified_name'], package['user_profile_set'], user['expiry'] if 'expiry' in user else batch['expiry']) 
						print 'addUser', adduser
						try:
							if 'target' in adduser and 'error' in adduser['target']:
								print 'ADDUSER ERROR', adduser
								self.log.info('Login.end system_error [%s]: Unable to provision initial login', subscriber_id)
								flash(self.model.spiel('system_timeout', code='7719a'), 'error')
								return redirect(url_for('login_form'))
			
						except Exception, err:
							print 'exception error on adduser', err
							self.log.info('Login.end system_error [%s]: Unable to provision initial login (exception)', subscriber_id)
							flash(self.model.spiel('system_timeout', code='22d20'), 'error')
							return redirect(url_for('login_form'))

						self.model.vms_db.batch_users.update({'_id': ObjectId(user['_id'])}, {'$set': {'stage': 2}})
			
					#~ STAGE 2. ADD SESSION RIGHT
					if case(2):
						self.log.info('Adding prepaid session right %s to %s', package, subscriber_id)
						if package['usage_type'] == 'time':
							addsessionright = request.bpc.AddTimeSessionRight(subscriber_id=subscriber_id, validity=package['credit_validity'], time=package['cap'], data='Time_PLDT_WiFi_Prepaid')
						elif package['usage_type'] == 'volume-aggregate':
							addsessionright = request.bpc.AddVolumeSessionRight(subscriber_id=subscriber_id, validity=package['credit_validity'], volume=package['cap'], data='Volume_PLDT_WiFi_Prepaid')
						elif package['usage_type'] == 'volume-downlink':
							addsessionright = request.bpc.AddVolumeSessionRight(subscriber_id=subscriber_id, validity=package['credit_validity'], volume=package['cap'], data='Volume_PLDT_WiFi_Prepaid', direction='downlink')
						elif package['usage_type'] == 'volume-uplink':
							addsessionright = request.bpc.AddVolumeSessionRight(subscriber_id=subscriber_id, validity=package['credit_validity'], volume=package['cap'], data='Volume_PLDT_WiFi_Prepaid', direction='uplink')
		
						if type(addsessionright) == type({}) and 'success' in addsessionright:
							self.log.info('Prepaid SR id %s successfully added to %s', addsessionright['success']['session-right']['id'], subscriber_id)
						else:
							self.log.info('Failed Adding SR %s to %s', package, subscriber_id)
							session.destroy()
							flash(self.model.spiel('system_timeout', code='c1dfd'), 'error')
							return redirect(url_for('login_form'))		
						
						self.model.vms_db.batch_users.update({'_id': ObjectId(user['_id'])}, {'$set': {'status': 3, 'remarks': 'None', 'stage': 3}})

				self.model.vms_tag_activated(username)
			password = user['hash_password']
		
		#
		# Post Paid	
		else:	
			# MD5 Hash the password (NOT SECURE)
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
			aaa_user_name = getuser['target']['result']['user']['name']
			aaa_user_status = getuser['target']['result']['user']['status']['value']
			aaa_user_password = getuser['target']['result']['user']['password']['value']
			aaa_user_profile_set = getuser['target']['result']['user']['profile-set']['name'] 
		except Exception as ex:
			self.log.error('Login.end system_error [%s]: Getuser parsing: %s, %s', subscriber_id, getuser, ex)
			flash(self.model.spiel('system_timeout', code='77de6'), 'error')
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
		# NOTE: double checking on prepaid
		if aaa_user_password != password:
			flash(self.model.spiel('incorrect_credentials'), 'error')
			self.log.info('Login.end user_error [%s]: Incorrect password', subscriber_id)
			return redirect(url_for('login_form'))
	
		# Login OK
		
		#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
		# Portal Session is now Valid
		#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
		session['Subscriber-Id'] = subscriber_id
		session['Password'] = password
		session['Profile-Set'] = aaa_user_profile_set
		#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
		# Portal Session is now Valid
		#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!		
			
		if paytype == 'prepaid':
			if 'prepaid_last_login_attempt' in session:
				prepaid_last_login_attempt_elapsed = time.time() - session['prepaid_last_login_attempt']	
				print 'ELAPSES', prepaid_last_login_attempt_elapsed
				waitfor = 10
				if prepaid_last_login_attempt_elapsed < waitfor:
					#time.sleep(waitfor - prepaid_last_login_attempt_elapsed)				
					return 'Login too fast!'
					
			session['prepaid_last_login_attempt'] = time.time()
			
			# Iterate over the session rights
			if not request.bpc.process_session_rights(session, ignore_base=True):
				session.destroy()
				self.log.error('Login.end system_error [%s]: BPC session rights processing returned False', subscriber_id)
				flash(self.model.spiel('system_timeout', code='1b645'), 'error')
				return redirect(url_for('login_form'))		

			# Intercept blank session rights
			if session['rights'] == {}:
				self.log.info('Login.end user_error [%s]: Session rights empty', subscriber_id)
				session.destroy()
				flash(self.model.spiel('quota_depleted'), 'error')
				return redirect(url_for('login_form'))

			self.model.vms_tag_last_accessed(username)
				
		elif paytype == 'postpaid':
			# Validate Kenan
			self.log.info('Sending AccessTag query to kenan for %s', subscriber_id)
			print 'aaauser', aaa_user_name
			access_tag = request.kenan.AccessTag(aaa_user_name)	
			if access_tag == False:
				self.log.error('Login.end user_error [%s]: PLDT kenan accesstag webservice timedout', subscriber_id)
				session.destroy()
				flash(self.model.spiel('system_timeout', code='0ade7'), 'error')
				return redirect(url_for('login_form'))

			access_tag = int(access_tag)

			if access_tag <= 0:
				self.log.error('Login.end user_error [%s]: PLDT kenan webservice returned %s', subscriber_id, access_tag)
				session.destroy()
				flash(self.model.spiel('system_timeout', code='b1d57'), 'error')
				return redirect(url_for('login_form'))
			
			if access_tag >= 2:
				self.log.error('Login.end user_error [%s]: PLDT kenan rejected the subscriber', subscriber_id)
				session.destroy()
				kenan_results = {2: 'Disallow', 3: 'Permanently Disallow'}
				flash('Not allowed. Kenan returned "%s"' % (kenan_results[access_tag]), 'error')
				return redirect(url_for('login_form'))
			
			self.log.info('Kenan has allowed %s.', subscriber_id)

			# Check security question
			self.log.info('Checking security question for %s', subscriber_id)
			getusersq = request.kenan.GetUserSecurityQuestion(orig_username)
			print 'SQ', getusersq
#				self.log.error('Login.end user_error [%s]: PLDT kenan security question webservice returned ', subscriber_id)
#				session.destroy()
#				flash(self.model.spiel('system_timeout', code='0716d'), 'error')
#				return redirect(url_for('login_form'))
			
			# force redirect
			if type(getusersq) == type({}):
				if getusersq['id'] == '0':
					session['force_update_sq'] = True
					return redirect('/pldt/auth?sq')
			
		return self._do_account_logon(subscriber_id, password)

	def _do_account_logon(self, subscriber_id, password):
		del(session['Password'])
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

		self.model.save_login_time(session['Subscriber-Id'])
		self.log.info('Login.end ok [%s]', subscriber_id)
		
		request.response.headers.add('X-Login-Successful', '1')		
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
		request.gateway_session.logoff(request.gateway_session_id)
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

		metering_ok = True
		metered = False

		if not postpaid_check.match(session['Subscriber-Id']):
			#print 'status_session1', session
			psr = request.bpc.process_session_rights(session, ignore_base=True)
			#print 'process_session_rights', psr
			#print 'status_session2', session
	
			if 'account_type' in session:		
				metered = True
				if not psr: #request.bpc.process_session_rights(session, force=True):
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

		request.response.headers.add('X-Status-Metered', metered)
		if metered and metering_ok:
			request.response.headers.add('X-Status-Balance', session['balance_bit'])
		
		request.response.data = render_template_string(request.templates['status'], templates=request.template_objects, sess=session, metered=metered, metering_ok=metering_ok, subscriber_ip=session['IP-Address'], subscriber_id=session['Subscriber-Id'])
		return request.response
	
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


	# Lost Password Form
	#
	def lost_password_form(self):
		if 'do' in request.args and request.args['do'] == 'captcha_img':
			if 'pw_captcha' not in session:
				abort(503)			
			else:
				response = make_response(session['pw_captcha'].image())
				response.headers.add('Content-Type', 'image/png')
				return response 

		phase = int(request.args['phase']) if 'phase' in request.args else 1

		if phase == 1:
			session.wipe(exception_keys=['_flashes'])
			session['confirmation_form_type'] = 'lost_password'
			request.response.data = render_template_string(request.templates['lost_password1'], templates=request.template_objects)
			
		elif phase == 2 and 'confirmation_email_address' in session:
			session['security_qa'] = security_qa = request.kenan.GetUserSecurityQuestion(session['confirmation_email_address'])	
			if security_qa == False:
				self.log.info('Lost password for %s kenan security question query failed', session['confirmation_email_address'])
				session.destroy()
				flash(self.model.spiel('system_timeout', code='17ba0'), 'error')
				return redirect(url_for('lost_password_form'))			
			request.response.data = render_template_string(request.templates['lost_password2'], security_qa=security_qa, templates=request.template_objects)
			
		elif phase == 3 and 'confirmation_answer_ok' in session:
			if 'pw_captcha' not in session:
				session['pw_captcha'] = captcha(request.gateway_session_id)
				self.log.info('Captcha Validation: %s', session['pw_captcha']._generate_words())
			request.response.data = render_template_string(request.templates['lost_password3'], templates=request.template_objects)
			
		else:
			return redirect('/lost_password?phase=1')
			
		return request.response		
			
	#	
	# Lost Password Submit
	#	
	def lost_password_submit(self):
		formtype = 'lost_password'
		phase = int(request.form['phase']) if 'phase' in request.form else 1
		self.log.info('Lost password submit phase %s', phase)
		print session
		if len(session) == 0:
			self.log.debug('Session is empty. Ejecting.')
			return redirect(url_for('login_form'))

		# Phase 1: Email Address Entry
		if phase == 1:
			if 'confirmation_activation_ok' in session:
				del(session['confirmation_activation_ok']) 

			# Valid Email check
			email_address = str(request.form['user_id']) if 'user_id' in request.form else ''

			if email_address == '':
				self.log.info('Invalid User Id (email) %s', email_address)
				session.destroy()
				flash(self.model.spiel('invalid_email_address'), 'error')
				return redirect(url_for('lost_password_form'))			
			
			if not self.model.check_email_address(email_address):
				self.log.info('Invalid User Id (email) %s', email_address)
				session.destroy()
				flash(self.model.spiel('invalid_email_address'), 'error')
				return redirect(url_for('lost_password_form'))
			
			getuser = request.sdb.getUser(email_address.replace('@', ':'), self.config['postpaid_domain'])
			if getuser == False:
				self.log.error('SDB.getUser returned False')
				flash(self.model.spiel('system_timeout', code='7b520'), 'error')
				return redirect(url_for('login_form'))			
			
			# User does not exist
			if 'error' in getuser['target']:
				self.log.info('Lost Password: account %s does not exist.', email_address)
				session.destroy()
				flash(self.model.spiel('invalid_account'), 'error')				
				return redirect(url_for('lost_password_form'))
			# User Exists
			else:
				session['confirmation_email_address'] = email_address

				if request.entrypoint_redirected:
					return redirect(network_path_url_for('%s_form' % (formtype)) + '?phase=2')
				else:
					return redirect(url_for('lost_password_form') + '?phase=2')
			
		# Phase 2: Security Answer Entry
		elif phase == 2 and 'security_qa' in session:
			submitted_security_answer = request.form['security_answer'] if 'security_answer' in request.form else ''
			
			self.log.debug('Compare [%s]=[%s]', submitted_security_answer, session['security_qa']['answer'])
			if submitted_security_answer.lower() == session['security_qa']['answer'].lower():
				self.log.debug('Answer to the security question correct.')
				session['confirmation_answer_ok'] = True
				return redirect(url_for('lost_password_form') + '?phase=3')				
			else:
				self.log.debug('Answer to the security question incorrect.')
				flash(self.model.spiel('incorrect_security_answer'), 'error')			
				return redirect(url_for('lost_password_form') + '?phase=2')				
		
		# Phase 3: Password entry
		elif phase == 3 and 'confirmation_answer_ok' in session:
			if 'password1' not in request.form or 'password2' not in request.form:
				self.log.debug('Password1 and Password2 is not present on the submitted data.')
				return redirect(url_for('lost_password_form') + '?phase=3')				

			if request.form['password1'] != request.form['password2']:
				self.log.debug('Password confirmation does not match.')
				flash(self.model.spiel('password_match_error'), 'error')			
				return redirect(url_for('lost_password_form') + '?phase=3')				
			
			submitted_password = request.form['password1']
			# No password validation yet
			#if not self.model.validate_password(submitted_password):
			#	self.log.debug('Invalid Password')
			#	flash(self.model.spiel('invalid_password'), 'error')			
			#	return redirect(url_for('lost_password_form') + '?phase=3')				
			
			if 'captcha' in request.form and 'pw_captcha' in session:
				self.log.info('CAPTCHA entered: %s expected: %s', request.form['captcha'], session['pw_captcha']._generate_words())
				if session['pw_captcha'].verify(request.form['captcha']):
					self.log.info('CAPTCH MATCH')
					del(session['pw_captcha'])
				else:				
					self.log.debug('Password confirmation does not match.')
					flash(self.model.spiel('incorrect_captcha'), 'error')
					return redirect(url_for('lost_password_form') + '?phase=3')			
			
			# Hash the password
			submitted_password = utils.password_hash(submitted_password)
			
			# Send updateUser API call to BWS SDB
			change_password = request.sdb.changePassword(session['confirmation_email_address'].replace('@', ':'), submitted_password)
			try:
				if 'target' in change_password and 'error' in change_password['target']:
					self.log.info('UpdateUser Error: %s %s', change_password['target']['error']['code'], change_password['target']['error']['message'])
					change_password = False
			except Exception, err:
				if change_password == False:
					self.log.info('UpdateUser connection timed out.')
				else:
					self.log.info('UpdateUser Exception: %s', err)
				change_password = False

			if change_password == False:
				flash(self.model.spiel('system_timeout', code='fa35e'), 'error')
				return redirect(url_for('lost_password_form') + '?phase=3')			
			
			# Send an email API to PLDT
			# are we going to show a spiel if this fails?
			send_email = request.kenan.ResetPassword(session['confirmation_email_address'])
			if send_email == False:
				pass
			else:
				send_email = int(send_email)
				if send_email <= -1:
					#error
					pass
				elif send_email >= 1:
					#error
					pass
				#ok			
				
			print send_email, type(send_email)
			
			session.wipe(exception_keys=['_flashes'])
			flash('successful change password spiel', 'info')
			return redirect('/')
		else:
			return redirect('/lost_password?phase=1')		

	#
	# Change info form
	#  - Password
	#  - Security QA
	#
	def change_password_form(self):
		user = self.model.get_user_info_from_session()
		if not user:
			return abort(403)
		
		# only postpaid users allowed
		if user['domain'] not in ('postpaid.wifi.pldt.com.ph'):
			return abort(403)
		
		if 'sq' in request.args:
			if not self.model.security_questions:
				secqs = request.kenan.GetSecurityQuestions()
				if secqs == False:
					self.log.error('Security question fetch failed.')
					flash(self.model.spiel('system_timeout', code='63266'), 'error')
					return redirect('/pldt/status')		

				self.model.security_questions = secqs
				request.log('SEQQ %s', self.model.security_questions)

			request.response.data = render_template_string(request.templates['change_security_qa'], security_questions=self.model.security_questions, templates=request.template_objects)
			return request.response					
		else:
			request.response.data = render_template_string(request.templates['change_password'], templates=request.template_objects)
			return request.response		
		
		
	def change_password_submit(self):
		user = self.model.get_user_info_from_session()
		if not user:
			return abort(403)
		
		# only postpaid users allowed
		if user['domain'] not in ('postpaid.wifi.pldt.com.ph'):
			return abort(403)
		
		# CHANGE SECURITY QUESTION/ANSWER
		if 'sq' in request.args:
			print 'form', request.form
			if 'sq_question' not in request.form or 'sq_answer' not in request.form:
				return abort(403)
		
			update_sq = request.kenan.UpdateUserSecurityQuestion(user['user_id'], request.form['sq_question'], request.form['sq_answer'])
			if type(update_sq) != type(u''):
				self.log.error('Security question update failed. Connection timed out.')
				flash(self.model.spiel('system_timeout', code='f1abd'), 'error')
				return redirect('/pldt/change_password?sq')		
			
			update_sq = int(update_sq)
			
			if update_sq == 0:
				self.log.info('Security question update successful!')
				flash('security question update success spiel (changeme)')
				return redirect('/pldt/status')
			else:
				self.log.error('Security question update failed. Error code %s returned.', update_sq)
				flash(self.model.spiel('system_timeout', code='1574b'), 'error')
				return redirect('/pldt/change_password?sq')		
				
		# CHANGE PASSWORD
		else:
			old_password = str(request.form['old_password'])
			new_password = str(request.form['new_password'])
			confirm_password = str(request.form['confirm_password'])
			old_password_md5 = utils.password_hash(old_password)

			# Check Current Password
			self.log.debug('Sending GetUser %s:%s', user['aaa_user_id'], old_password)
			getuser = request.sdb.getUser(user['aaa_user_id'], user['domain'])		
			if getuser == False:
				self.log.error('SDB.getUser returned False')
				flash(self.model.spiel('system_timeout', code='4d134'), 'error')
				return redirect(url_for('chpasswd_form'))
				
			if 'error' in getuser['target']:
				self.log.error('SDB.getUser returned invalid contents')
				flash(self.model.spiel('system_timeout', code='f6e11'), 'error')
				return redirect(url_for('chpasswd_form'))
		
			try:
				aaa_user_status = getuser['target']['result']['user']['status']['value']
				aaa_user_password = getuser['target']['result']['user']['password']['value']
			except Exception as ex:
				self.log.error('ChangePassword error: %s@%s Getuser parsing: %s, %s', user['aaa_user_id'], user['domain'], getuser, ex)
				flash(self.model.spiel('system_timeout', code='88730'), 'error')
				return redirect(url_for('chpasswd_form'))
			
			# Check Old Password
			if aaa_user_password != old_password_md5:
				self.log.info('Change Password: Incorrect current password')		
				flash(self.model.spiel('incorrect_old_password'), 'error')	
				return redirect(url_for('chpasswd_form'))
	
#			if not self.model.validate_password(new_password):
#				self.log.info('Change Password: Invalid new password')		
#				flash(self.model.spiel('invalid_password'), 'error')			
#				return redirect(url_for('chpasswd_form'))
				
			if new_password != confirm_password:
				self.log.info('Change Password: Password confirmation does not match')		
				flash(self.model.spiel('password_match_error'), 'error')			
				return redirect(url_for('chpasswd_form'))
				
			if old_password == new_password:
				self.log.info('Change Password: Invalid new password (same as the old one)')		
				flash(self.model.spiel('change_password_same_old'), 'error')			
				return redirect(url_for('chpasswd_form'))


			submitted_password = utils.password_hash(new_password)
			
			# Send updateUser API call to BWS SDB
			change_password = request.sdb.changePassword(user['aaa_user_id'], submitted_password)
			try:
				if 'target' in change_password and 'error' in change_password['target']:
					self.log.info('UpdateUser Error: %s %s', change_password['target']['error']['code'], change_password['target']['error']['message'])
					change_password = False
			except Exception, err:
				if change_password == False:
					self.log.info('UpdateUser connection timed out.')
				else:
					self.log.info('UpdateUser Exception: %s', err)
				change_password = False

			if change_password == False:
				flash(self.model.spiel('system_timeout', code='fa35e'), 'error')
				return redirect(url_for('chpasswd_form') + '?phase=3')			

			flash('successful change password spiel', 'info')
	
#			new_password_md5 = utils.password_hash(new_password)
#			change_pw = request.sdb.changePassword(user['aaa_user_id'], new_password_md5)
#			print 'change_pw', change_pw
										
			return redirect(url_for('status_page'))
