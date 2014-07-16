import pyrad.packet
from pyrad.client import Client
from pyrad.dictionary import Dictionary
import hashlib
from itertools import cycle, izip

class Session:
	def __init__(self, gateway, log):
		self.log = log
		self.config = gateway
		self.endpoint = gateway['ip_address']
		self.session = {}

	def extract_session_id(self, environ):
		return 'L%s' % (environ['REMOTE_ADDR'])		
	
	def session_sync(self, request, session):
		print 'ARGS', request.args
		if 'loopback_session' not in session:		
			return False

		self.log.debug('Reinitiating portal session. Subscriber Id: %s IP: %s', session['Subscriber-Id'], session['IP-Address'])
		return True
		
	def logon(self, subscriber_id, password, sess_id):
		self.log.debug('Loopback account logon for %s', sess_id)
		self.session['loopback_session'] = True
		self.session['loopback_session_id'] = hashlib.md5(sess_id).hexdigest()

		self.session['Subscriber-Id'] = subscriber_id
		self.session['IP-Address'] = '127.0.0.1'
		#session['Gateway-Session'] = True
		
		return True, None, {}

	def logoff(self, sess_id):
		self.log.debug('Clearing loopback session %s sess_id', sess_id)

		self.session = {}

		return True, None
	
