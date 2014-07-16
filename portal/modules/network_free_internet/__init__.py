### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### 
# Smart WiFi - Captive Portal
# ## ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ##
#
# Smart Phase 1 Network Module
#
# Valid session: if 'Subscriber-Id' in session 

from flask import url_for as flask_url_for, request, make_response, render_template, render_template_string, flash, redirect, abort, session
from captcha import captcha
from piechart import PieChart
import utils, time, datetime, pymongo, json, re, hashlib

# endpoint with network path support
def url_for(endpoint):
	if type(request.view_args) == type({}) and 'path' in request.view_args:
		return '%s%s' % (request.view_args['path'], flask_url_for(endpoint))
	return flask_url_for(endpoint)
	
#
# Network Data Model
#
class Model:
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
					
			self.logins = self.db.logins
			self.session_infos = self.db.session_infos
			#self.registrations = self.db.registrations # Registration Tracking
			self.sps_requests = self.db.sps_requests
			self.confirmations = self.db.confirmations # SMS Throttling			
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
			self.log.error('MongoDB sess_info_login_time error:' % (err))
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
		username = hashlib.md5(request.gateway_session_id).hexdigest()[:16]
		password = 'free'
		domain = 'freewifi.smart.com.ph'
	
		subscriber_id = '%s@%s' % (username, domain)
		self.log.info('Login.start [%s]: password is ***', subscriber_id)
		
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
		request.session_age = self.model.get_session_age(session['Subscriber-Id'])
				
		request.response.data = render_template_string(request.templates['status'], templates=request.template_objects, sess=session, metered=metered, metering_ok=metering_ok, subscriber_ip=session['IP-Address'], subscriber_id=session['Subscriber-Id'])
		return request.response
