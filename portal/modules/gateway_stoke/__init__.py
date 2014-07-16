#
# Stoke SSX Gateway Interface
#
# https://10.169.9.50/?loginurl=https://10.169.9.50/&ssx_ip=10.254.61.248&ssx_port=80&user_ip=10.255.136.114&client_mac=74-de-2b-4d-1d-c2&userurl=http://cnn.com/&challenge=e18c0410
#
import pyrad.packet
from pyrad.client import Client
from pyrad.dictionary import Dictionary
import hashlib
from itertools import cycle, izip

CoAACK = 44
CoANAK = 45

class coa:
	endpoint = None
	shared_secret = None
	def __init__(self, endpoint, shared_secret):
		self.endpoint = endpoint
		self.shared_secret = shared_secret
		
		self.srv = Client(server=self.endpoint, authport=3799, secret=self.shared_secret, dict=Dictionary('dictionary'))
		self.srv.retries = 1

	def _xor(self, ss, key):
	    key = cycle(key)
	    return ''.join(chr(ord(x) ^ ord(y)) for (x,y) in izip(ss, key))

	def chunks(self, l, n):
		return [l[i:i+n] for i in range(0, len(l), n)]

	def makeCiscoSubscriberPassword(self, password, I='IIIIIIIIIIIIIIII'):
		c = [] # ciphertexts
		b = [hashlib.md5(self.shared_secret + I).hexdigest()] 
		P = '%s%s' % (hex(len(password))[2:].rjust(2, '0').decode('hex'), password)
		Pchunked = self.chunks(P, 16)
		
		for i, pi in enumerate(Pchunked):
			if len(pi) != 16:
				pi = pi.ljust(16, '\x00')
			pi = pi.encode('hex')
			if i != 0:
				b.append(hashlib.md5(self.shared_secret + c[i-1]).hexdigest())
			c.append(self._xor(pi.decode('hex'), b[i].decode('hex')))
		
		cisco_password = I + ''.join(c)
		return cisco_password


	def logon(self, username, password, calling_station_id, sess_id):
		self.reply = None

		req = self.srv.CreateCoAPacket()
		req['User-Name'] = username
		req['Calling-Station-Id'] = calling_station_id
		#req['Subscriber-Password'] = self.makeCiscoSubscriberPassword(password)
		#req['Cisco-AVPair'] = 'subscriber:command=account-logon'		
		#req['Cisco-Account-Info'] = sess_id
		print 'Sending', req
		reply = self.srv.SendPacket(req)
		ret = {}
		print 'Reply', reply.code, reply
		for i in reply.keys():
			try:
				ret[i] = reply[i]
			except Exception as err:
				print 'coa response parsing warning for attribute', i, err
				continue
		
		return (reply.code, ret)
		
	def logoff(self, sess_id):
		self.reply = None
	
		req = self.srv.CreateCoAPacket()
		req['User-Name'] = ''
		req['Cisco-AVPair'] = 'subscriber:command=account-logoff'

		req['Cisco-Account-Info'] = sess_id

		reply = self.srv.SendPacket(req)

		ret = {}
		for i in reply.keys():
		    ret[i] = reply[i]
		
		return (reply.code, ret)
			
	def query(self, sess_id):
		self.reply = None
	
		req = self.srv.CreateCoAPacket()
		req['User-Name'] = ''
		req['Cisco-AVPair'] = 'subscriber:command=account-status-query'

		req['Cisco-Account-Info'] = sess_id

		reply = self.srv.SendPacket(req)

		ret = {}
		for i in reply.keys():
		    ret[i] = reply[i]
		
		return (reply.code, ret)

class Session:
	def __init__(self, gateway, log):
		self.log = log
		self.config = gateway
		self.endpoint = gateway['ip_address']
		self.shared_secret = str(gateway['shared_secret'])
		self.coa = coa(self.endpoint, self.shared_secret)
		self.calling_station_id = ''

	def extract_session_id(self, environ):
		return 'S%s' % (environ['REMOTE_ADDR'])		
	
	# Assume no session for now
	def session_sync(self, request, session):
#		session['Calling-Station-Id'] = request.args['Calling-Station-Id']
		print 'ARGS', request.args
		self.calling_station_id = request.args.get('client_mac', '')
		return False
	
	def status(self, sess_id):
		pass
		#return True, query[1]
			
	def logon(self, subscriber_id, password, sess_id):
		self.log.debug('Sending Account Logon CoA for session id %s', sess_id)
		print 'CALLING STATION ID LOGON', self.calling_station_id

		try:
			logon = self.coa.logon(subscriber_id, password, self.calling_station_id, sess_id)
			self.log.debug('Login Reply: %s', logon)
			if logon[0] == CoANAK:
				logoff = self.coa.logoff(sess_id)
				if 'Reply-Message' in logon[1]:
					return False, ' '.join(logon[1]['Reply-Message']), logon[1]
				return False, 'CoANAK', {}
		except Exception as err:
			self.log.error('CoA-logon Error: %s', err)			
			return False, err, {}
			
		if 'Reply-Message' in logon[1]:
			return False, ' '.join(logon[1]['Reply-Message']), logon[1]
	
		self.log.debug('CoA logon result: %s', logon)
		return True, None, logon[1]
	
	def logoff(self, sess_id):
		self.log.debug('Sending Account Logoff CoA for session id %s', sess_id)

		try:
			logoff = self.coa.logoff(sess_id)
		except Exception as err:
			self.log.error('CoA Error', err)			
			return False, err
			
		self.log.debug('CoA logoff result: %s', logoff)
		return True, None
	
