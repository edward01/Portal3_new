###########################################################################################
# PLDT-Smart WiFi - Captive Portal
###########################################################################################
#
# PLDT/Smart entrypoint
#

import re
import time
import utils
import pkgutil
from flask import url_for, request, make_response, render_template_string, flash, redirect, abort, session
from captcha import captcha

roaming_domains = []
for partner in [name for _, name, _ in pkgutil.iter_modules(['roaming'])]:
	g = __import__('roaming.%s' % (partner), fromlist=['*'])	
	try:
		roaming_domains.append(g.domain)
	except Exception as ex:
		continue
	
#
# Network Data Model
#
class Model:
	spiels = {
		'quota_depleted': "Your Wi-Fi account has expired/has been fully consumed.",
		'logout': "You have successfully logged out of your WiFi Session.",
	}
	
	domain_networks = {
		'prepaid.wifi.pldt.com.ph': 'pldt',
		'postpaid.wifi.pldt.com.ph': 'pldt',
		'vip.wifi.pldt.com.ph': 'pldt',
		'3gpp.smart.com.ph': 'smart',
		'docomo': 'roaming'
	}
	
	def __init__(self):
		for roaming_domain in roaming_domains:
			self.domain_networks[roaming_domain] = 'roaming'
	
	re_msisdn = re.compile('^\d+$')
	def network_selector(self, networks):
		if request.endpoint == 'login_submit':
			if 'Pangolin' in request.headers.get('User-Agent', ''):
				return networks[self.config['_entrypoint_networks'][2]]
		
			# defaults to PLDT
			if 'principal' not in request.form:
				return networks[self.config['_entrypoint_networks'][0]]
			
			# Smart
			if self.re_msisdn.match(str(request.form['principal'])):
				return networks[self.config['_entrypoint_networks'][1]]

			# PLDT
			else:
				return networks[self.config['_entrypoint_networks'][0]]

		elif request.endpoint == 'lost_password_submit': 
			# defaults to PLDT
			if 'user_id' not in request.form:
				return networks[self.config['_entrypoint_networks'][0]]
			
			# Smart
			if self.re_msisdn.match(str(request.form['user_id'])):
				request.form = request.form.copy()
				request.form['mobile_number'] = request.form['user_id']
				return networks[self.config['_entrypoint_networks'][1]]

			# PLDT
			else:
				return networks[self.config['_entrypoint_networks'][0]]

	def get_session_age(self, subscriber_id):
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
		
		if 'force_update_sq' in session:
			return redirect('/pldt/auth?sq')
				
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
			print 'Checking for accounting stop..'
			for n in range(4):
				sessacct = self.model.getSessionByIP()
				print '  ', sessacct

				if not sessacct:
					break

				if sessacct['Acct-Status-Type'] == 'Stop':
					break
				time.sleep(1)
			print 'woke up'
			for n in range(4):
				sc = request.gateway_session.session_sync(request, session)
				print 'sc', sc
				if not sc:
					break
				time.sleep(1)		
				
		session['Gateway-Session'] = False
		return redirect(url_for('login_form'))
		
		
	#
	# Status
	#
	def status(self):
		if 'Subscriber-Id' in session:
			subscriber_id = session['Subscriber-Id']
			if subscriber_id.find('@') == -1:
				self.log.info('Status Entrypoint: Invalid Subscriber ID %s', subscriber_id)
				return abort(403)
			
			username, domain = subscriber_id.split('@')
			
			if domain not in self.model.domain_networks:
				self.log.info('Status Entrypoint: Invalid Domain %s', domain)
				return abort(403)
			
			status_redirect = '/%s%s' % (self.model.domain_networks[domain], url_for('status_page'))
			self.log.info('Status entrypoint redirecting to %s', status_redirect)
			return redirect(status_redirect)

		else:
			self.log.info('Status Entrypoint: No subscriber id in session')
			return abort(403)
		

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


	#
	# Register Form
	#
	def register_form(self):
		request.response.data = render_template_string(request.templates['register_selection'], templates=request.template_objects)
		return request.response	


	#
	# Lost Password Form
	#
	def lost_password_form(self):
		phase = int(request.args['phase']) if 'phase' in request.args else 1
		self.log.info('Lost Password entrypoint form phase %s', phase)

		if phase == 1:
			session.wipe(exception_keys=['_flashes'])
			session['confirmation_form_type'] = 'lost_password'
			request.response.data = render_template_string(request.templates['lost_password1'], templates=request.template_objects)
		else:
			return redirect(url_for('lost_password_form') + '?phase=1')		
		return request.response	
		