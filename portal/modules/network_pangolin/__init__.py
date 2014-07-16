### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### 
# Converged Core - Pangolin WISPr endpoint
# ## ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ##
#

from flask import url_for as flask_url_for, request, make_response, render_template, render_template_string, flash, abort, session, redirect
from captcha import captcha
from piechart import PieChart
import utils, time, datetime, pymongo, json, re, pymongo_safe, hmac, hashlib

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
	def connect(self):
		model_config = self.config['model_config']
		self.log.debug('Connecting to mongod..')

		connections = pymongo_safe.MongoHandler(model_config)
		self.db = connections['portal_smart_wifi'][model_config['portal_smart_wifi']['name']]
		self.mdb = connections['mobile'][model_config['mobile']['name']]
			
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

	def validate_password(self, passwd):
		if len(passwd) >= 8 and len(passwd) <= 16:
			if re.search('[a-zA-Z]+', passwd) and re.search('[0-9]+', passwd):    	
				return True
		return False  

	def before_request(self):
		request.url_for = url_for

#
# HMAC Security
#
def sortedparameters(parameters):
	output = []
	for key in sorted(parameters.iterkeys()):
	    output.append("%s=%s" % (key, parameters[key]))
	return '?' + '&'.join(output)

def hmacdigest(method, resource, parameters, nonce, utctimestamp, udid):
	concat = str('%s%s%s%s:%s' % (method, resource, parameters, nonce, utctimestamp)).lower()
	udid = str(udid)
	print 'CONCAT', concat, 'UDID', udid
	return hmac.new(udid, concat, hashlib.sha256).hexdigest()
	
#
# Network Actions
#
class Actions:
	#
	# Auto Login
	#
	def login_submit(self):
		if 'X-Auth' not in request.headers:
			self.log.debug('Autologin failed: Request signature is missing.')
			return abort(404)

		if 'X-Timestamp' not in request.headers:
			log.info('X-Auth: Timestamp parameter missing')
			return abort(404)

		sutctimestamp = int(calendar.timegm(time.gmtime()))
		cutctimestamp = int(request.headers.get('X-Timestamp', ''))
		timestamp_diff = abs(sutctimestamp - cutctimestamp)
		log.debug('X-Timestamp server=%s client=%s', sutctimestamp, cutctimestamp)
		log.debug('X-Timestamp timestamp difference is %s seconds', timestamp_diff)
		if timestamp_diff > security_nonce_lifetime:
			log.info('X-Auth: Timestamp out of bounds')
			return abort(403)
			
		xauth = request.headers.get('X-Auth')
		uid = xauth[:40]
		hmac_digest = xauth[40:104]
		nonce = xauth[-7:]
		client = self.model.mdb.clients.find_one({'_id': uid})							

		if client is None:
			log.info('X-Auth: UID %s not found.', uid)
			return abort(401)

		print 'method', request.method, 'path', request.path, request.values
		computed_hmac_digest = hmacdigest(request.method, request.path, sortedparameters(request.values), nonce, client['udid'])
		print 'SENT HMAC', hmac_digest
		print 'COMPUTED HMAC', computed_hmac_digest

		if hmac_digest != computed_hmac_digest:
			log.info('X-Auth: Computed hmac mismatch')
			return abort(404)
		
#			rkey = 'nonce:%s:%s' % (nonce, uid)
#			rkey = 'nonce:%s' % hashlib.md5(uid + hmac_digest).hexdigest()
#			if redis.get(rkey):
#				log.info('X-Auth: Nonce %s for %s reused', nonce, uid)
#				return abort(404)			
#			redis.set(rkey, '1')
#			redis.expire(rkey, 3600)				

		username = client['msisdn']

		domain = self.config['domain']

		subscriber_id = '%s@%s' % (username, domain)
		self.log.info('Login.start [%s]: password is ***', subscriber_id)

		# MD5 Hash the password
		#password = utils.password_hash(password)
		
		# Check username & password
		self.log.info('Sending GetUser %s', username)
		getuser = request.sdb.getUser(username, domain)		
		
		if getuser == False:
			self.log.error('Login.end system_error [%s]: SDB.getUser returned False', subscriber_id)
			return abort(500)
			
		if 'error' in getuser['target']:
			if getuser['target']['error']['code'] == 'USR-00001':
				self.log.info('Login.end user_error [%s]: User does not exist', subscriber_id)
				return abort(401)
			else:
				self.log.error('Login.end system_error [%s]: SDB.getUser result code unknown', subscriber_id)
			return abort(500)
	
		try:
			aaa_user_status = getuser['target']['result']['user']['status']['value']
			aaa_user_password = getuser['target']['result']['user']['password']['value']
			aaa_user_profile_set = getuser['target']['result']['user']['profile-set']['name'] 
		except Exception as ex:
			self.log.error('Login.end system_error [%s]: Getuser parsing: %s', subscriber_id, getuser)
			return abort(500)
		
		if aaa_user_status == 'suspended':
			self.log.info('Login.end user_error [%s]: User suspended', subscriber_id)
			return abort(403)

		if aaa_user_status == 'pending':
			self.log.info('Login.end user_error [%s]: User suspended', subscriber_id)
			return abort(403)
		
		password = aaa_user_password
		
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
		if aaa_user_profile_set == '3G_UPS':
			# Iterate over the session rights
			if not request.bpc.process_session_rights(session):
				session.destroy()
				self.log.error('Login.end system_error [%s]: BPC session rights processing returned False', subscriber_id)
				return abort(500)

			# TTCs		
			#ttc_list = request.bpc.GetTTCList(subscriber_id)
			#self.log.debug('TTC LIST: %s', session['ttc_list'].keys())
		
			if session['rights'] == {}:
				self.log.info('Login.end user_error [%s]: Session rights empty', subscriber_id)
				session.destroy()
				return abort(403)
					
		# Send account-logon CoA to ISG
		self.log.info('Sending logon %s:%s to WAG..', subscriber_id, password)
		logon_result, logon_message, logon_attrs = request.gateway_session.logon(subscriber_id, password, request.gateway_session_id)
		if not logon_result:
			session.destroy()
			if type(logon_message) == type(u''):
				self.log.error('Login.end system_error [%s]: WAG login CoANaK: %s', subscriber_id, logon_message)				
			else:
				self.log.error('Login.end system_error [%s]: WAG session login returned CoANaK', subscriber_id)

			return abort(500)

		#!!!!!!!!!!!!!!!!!!!!!!!!!!!
		# GATEWAY SESSION NOW VALID
		#!!!!!!!!!!!!!!!!!!!!!!!!!!!
		session['Gateway-Session'] = True

		self.model.save_login_time(session['Subscriber-Id'])
		self.log.info('Login.end ok [%s]', subscriber_id)
		
		return u"""<HTML><!-
<?xml version="1.0" encoding="UTF-8"?>
<WISPAccessGatewayParam
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:noNamespaceSchemaLocation="http://www.wballiance.net/wispr/wispr_2_0.xsd">
   <AuthenticationReply>
       <MessageType>120</MessageType>
       <ResponseCode>50</ResponseCode>
       <MaxSessionTime>0</MaxSessionTime>
       <StatusURL>https://10.169.9.50/status</StatusURL>
       <LogoffURL>https://10.169.9.50/logoff</LogoffURL>
   </AuthenticationReply>
</WISPAccessGatewayParam>
--> </HTML>"""


	
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