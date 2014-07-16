class Session:
	def __init__(self, gateway, log):
		self.log = log
		self.config = gateway
		self.endpoint = gateway['ip_address']

	def extract_session_id(self, environ):
		return 'SCE_%s' % (environ['REMOTE_ADDR'])
		
	def session_sync(self, request, session):
		request.sdb = request.source['gateway']['sdb']
		request.sdb.failover(request)

		bws_session_status = request.sdb.getSessionByIp(request.environ['REMOTE_ADDR'])	
		if type({}) != type(bws_session_status):
			return False
		
		if 'error' in bws_session_status['target']:
			return False
		
		try:
			session['Subscriber-Id'] = '%s@%s' % (bws_session_status['target']['result']['device']['mac-address'].lower(), bws_session_status['target']['result']['device']['domain']['name'])
			session['BSID'] = bws_session_status['target']['result']['device']['bsid']
			session['IP-Address'] = request.environ['REMOTE_ADDR']
			session['Gateway-Session'] = True
			bws_user_info = request.sdb.getUser(bws_session_status['target']['result']['device']['mac-address'], bws_session_status['target']['result']['device']['domain']['name'])
			if 'error' not in bws_user_info['target']:
				session['Profile-Name'] = bws_user_info['target']['result']['user']['profile-set']['name']
		except Exception as ex:
			print 'session sync exception', ex
			return False