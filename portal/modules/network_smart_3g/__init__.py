# Smart WiMAX POC Network Class
#
from flask import url_for, request, make_response, render_template_string, flash, redirect, abort, session
import sms, utils, time, pymongo, datetime
import network_smart_wifi_ph1
print network_smart_wifi_ph1.Actions
class Actions(network_smart_wifi_ph1.Actions):
	#
	# Login Form
	#
	def login_form(self):
		#bws_session_status = request.sdb.getSessionByIp(request.environ['REMOTE_ADDR'])	
		print request.environ, request.headers
		bws_session_status = request.sdb.getSessionByIp('102.101.56.48')	
		
		if 'error' in bws_session_status['target']:
			return abort(403)
		subscriber_id = '%s@%s' % (bws_session_status['target']['result']['device']['mac-address'].lower(), bws_session_status['target']['result']['device']['domain']['name'])
		print bws_session_status

		#request.response.data = render_template('%s/login.html' % (request.template), message=bws_session_status)
		request.response.data = render_template_string(request.templates['login'], templates=request.template_objects, message=bws_session_status)
		return request.response
	
	#
	# Login Submit
	#
	def login_submit(self):
		

		# Send account-logon CoA to ISG
		self.log.info('Sending logon %s:%s to WAG..', subscriber_id, password)
		logon = request.gateway_session.logon(subscriber_id, password, request.gateway_session_id)
		if not logon[0]:
			self.log.debug('WAG account_logon CoA-NaK')
			session.destroy()
			flash('Service not available. Try again later.', 'error')
			return redirect(url_for('login_form'))
		session['Gateway-Session'] = True

		self.model.save_login_time(session['Subscriber-Id'])
		
		request.response.data = render_template_string(request.templates['welcome'], templates=request.template_objects)		
		return request.response
