#####################################################################
# Smart WiFi - Captive Portal
#####################################################################
# * Smart 7107 event free internet
#

import re
import utils
import hashlib
import datetime
import pymongo_safe
from flask import url_for, request, render_template_string, flash, redirect, session

#
# Network Data Model
#
class Model:
	valid_email_re = re.compile('^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$')
	valid_country_codes = ('63')
	valid_area_code = ('908', '918', '919', '920', '921', '928', '929', '939', '998', '999', '907', '909', '910', '912', '930', '946', '948', '938', '922', '923', '932', '933', '942', '943', '925')
	spiels = {
		'non_smart_msisdn': 'The number you entered is invalid. Please enter your Smart/Sun/Talk & Text number and try again.',
		'international_msisdn': 'Invalid country code',
	}

	def connect(self):
		model_config = self.config['model_config']
		self.log.debug('Connecting to mongod..')

		connections = pymongo_safe.MongoHandler(model_config)
		self.db = connections['portal_smart_wifi']['portal_smart_wifi']
		self.session_infos = self.db.session_infos
		self.sessions_7107 = self.db.sessions_7107
		self.subscribers_7107 = self.db.subscribers_7107
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
			session_info = self.session_infos.find_one({'_id': subscriber_id})
			if session_info is not None:
				td = datetime.datetime.now() - session_info['login_time']
				return utils.timedelta_str(td)
		except Exception as err:
			self.log.error('MongoDB sess_info_login_time error: %s' % (err))

		return ''

	def check_msisdn(self, msisdn):
		if len(msisdn) == 0:
			self.log.error('Invalid MSISDN: Empty')
			return False, None, self.spiels['non_smart_msisdn']

		if not msisdn.isdigit():
			self.log.error('Invalid MSISDN: Non-numeric character found')
			return False, None, self.spiels['non_smart_msisdn']

		if msisdn[0] == '0':
			msisdn = '63%s' % (msisdn[1:])

		if msisdn[0:2] not in self.valid_country_codes:
			self.log.error('Invalid MSISDN: Invalid country code')
			return False, None, self.spiels['international_msisdn']

		if len(msisdn) != 12:
			self.log.error('Invalid MSISDN: Invalid length')
			return False, None, self.spiels['non_smart_msisdn']

		if msisdn[2:5] not in self.valid_area_code:
			self.log.error('Invalid MSISDN: Invalid area code')
			return False, None, self.spiels['non_smart_msisdn']

		return True, msisdn, None


#
# Network Actions
#
class Actions:
	age_ranges = (
		('<=17', '17 and below'),
		('18-23', '18-23'),
		('24-29', '24-29'),
		('30-40', '30-40'),
		('>=41', '41 and above'),
	)

	#
	# Login Form
	#
	def login_form(self):
		print 'SESS', session
	
		if 'next' in request.args:
			next_page = request.args['next']
		else:
			next_page = utils.extract_nextpage(request, self.wide)
		session['next'] = next_page

		if 'q' in request.args and 'q' in session:
			template_name = 'loginq'
		else:
			template_name = 'login'
			if 'q' in session:
				del(session['q'])
		request.response.data = render_template_string(request.templates[template_name], templates=request.template_objects, age_ranges=self.age_ranges)
		return request.response

	#
	# Login Submit
	#
	def login_submit(self):
		#username = hashlib.md5(request.gateway_session_id).hexdigest()[:16]
		username = str(request.form['msisdn']) if 'msisdn' in request.form else None
		password = 'free'
		domain = 'freewifi.smart.com.ph'

		if username == None:
			return redirect(url_for('login_form'))

		# Check MSISDN input
		msisdn_valid, username, msisdn_error_message = self.model.check_msisdn(username)
		subscriber_id = '%s@%s' % (username, domain)
		self.log.info('Login.start [%s]: password is ***', subscriber_id)

		if not msisdn_valid:
			self.log.info('Login.end user_error [%s]: Invalid MSISDN: %s', subscriber_id, msisdn_error_message)
			flash(self.model.spiels['non_smart_msisdn'])
			return redirect(url_for('login_form'))

		msisdn_logged = self.model.subscribers_7107.find_one({'_id':username})

		if msisdn_logged is None:
			if 'email' in request.form and 'age_range' in request.form:
				email = request.form.get('email')
				age_range = request.form.get('age_range')
				gender = request.form.get('gender')

				if email is None or age_range is None or gender is None:
					flash('Incomplete parameters')
					self.log.info('Login.end user_error [%s]: Incomplete parameters', subscriber_id)
					return redirect(url_for('login_form') + '?q=1')

				if 'q' not in session:
					session['q'] = {'msisdn': username}
				session['q']['email'] = email
				session['q']['age_range'] = age_range
				session['q']['gender'] = gender

				if not self.model.valid_email_re.match(email):
					flash('Invalid email address')
					self.log.info('Login.end user_error [%s]: Invalid Email: %s', subscriber_id, email)
					return redirect(url_for('login_form') + '?q=1')

				if age_range == 'null':
					flash('Please select age range')
					self.log.info('Login.end user_error [%s]: No age range selection', subscriber_id)
					return redirect(url_for('login_form') + '?q=1')

				if gender == 'null':
					flash('Please select gender')
					self.log.info('Login.end user_error [%s]: No gender selection', subscriber_id)
					return redirect(url_for('login_form') + '?q=1')

				print 'STORE:', self.model.subscribers_7107.insert({'_id':username, 'email':email, 'age_range':age_range, 'gender':gender, 'timestamp':datetime.datetime.now()})
				self.log.info('Login.info [%s] Email[%s] AgeRange[%s] Gender[%s]', username, email, age_range, gender)

			else:
				self.log.info('First login attempt by %s, redirecting to form', username)
				session['q'] = {'msisdn': username}
				return redirect(url_for('login_form') + '?q=1')

		#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
		# Portal Session is now Valid
		#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
		session['Subscriber-Id'] = subscriber_id
		#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
		# Portal Session is now Valid
		#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

		# Send account-logon CoA to ISG
		self.log.info('Sending logon %s:%s to WAG..', subscriber_id, password)
		logon = request.gateway_session.logon(subscriber_id, password, request.gateway_session_id)
		if not logon[0]:
			self.log.error('Login.end system_error [%s]: WAG session login returned CoA-NaK', subscriber_id)
			session.destroy()
			if logon[1]:
				flash(logon[1], 'error')
			else:
				flash('coanak', 'error')
			return redirect(url_for('login_form'))
		session['Gateway-Session'] = True

		self.model.save_login_time(session['Subscriber-Id'])
		self.log.info('Login.end ok [%s]', subscriber_id)		
		self.model.sessions_7107.insert({'msisdn':username, 'user_agent':request.user_agent, 'ip_address':request.environ['REMOTE_ADDR']})		

		request.response.data = render_template_string(request.templates['welcome'], templates=request.template_objects)
		return request.response

	#
	# Logout
	#
	def logout(self, mesg):
		session.destroy()
#		if mesg == "depleted":
#			flash(self.model.spiel('quota_depleted'), 'error')
#		else:
#			flash(self.model.spiel('logout'), 'error')
		request.gateway_session.logoff(request.gateway_session_id)
		return redirect(url_for('login_form'))

	#
	# Status
	#
	def status(self):
		request.session_age = self.model.get_session_age(session['Subscriber-Id'])
		print 'TEMPLATES', request.templates.keys()
		request.response.data = render_template_string(request.templates['status'], templates=request.template_objects, sess=session, subscriber_ip=session['IP-Address'], subscriber_id=session['Subscriber-Id'])
		return request.response
