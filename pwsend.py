#!/usr/bin/python2

from cryptography.fernet import Fernet
import socket
import logging
import sys


bind_port = 1666
log_file = "/var/log/pwsend.log"
accepted_client = [ 192, 168, 1 ]
# Use Fernet.generate_key() to generate the key
secretKey = 'Rlpa0MfJ1WSflCNCFgfWU9s3c5FZa57Me3x2afLwBTc='
cutHereText = "-----CUT_HERE-----"


def get_passwd():
	foo = [x.split(':') for x in open('/etc/passwd').readlines()]
	passwd = []
	users = []
	for line in foo:
		pid = int(line[2])
		if pid >= 1000 and pid < 65000:
			passwd.append(':'.join(map(lambda x: x.strip(), line))+'\n')
			users.append(line[0].strip())
	text = ''.join(passwd)
	return text, users


def get_shadow(users):
	foo = [x.split(':') for x in open('/etc/shadow').readlines()]
	shadow = []
	for line in foo:
		uname = line[0].strip()
		if users.count(uname):
			shadow.append(':'.join(map(lambda x: x.strip(), line))+'\n')
	text = ''.join(shadow)
	return text


def get_group():
	foo = [x.split(':') for x in open('/etc/group').readlines()]
	groups = []
	for line in foo:
		gid = int(line[2])
		if gid >= 1000:
			groups.append(':'.join(map(lambda x: x.strip(), line))+'\n')
	text = ''.join(groups)
	return text




logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s', filename=log_file, filemode='a')
logging.info('Program started with command ' + sys.argv[0])
engine = Fernet(secretKey)

soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
soc.bind(('', bind_port))
soc.listen(10)
while 1:
	conn, addr = soc.accept()
	logging.info('Connection from %s port %d' % addr)
	a = map(int, addr[0].split('.'))
	if a[:3] != accepted_client:
		logging.warning('Connection from %s refused.' % (addr[0]))
		conn.close()
		continue
	passwd, users = get_passwd()
	shadow = get_shadow(users)
	group  = get_group()
	text  = engine.encrypt(passwd)
	text += cutHereText
	text += engine.encrypt(shadow)
	text += cutHereText
	text += engine.encrypt(group)
	try:
		data = conn.recv(1024)
	except socket.error as e:
		logging.info('socket.error [%d] %s' % (e.errno, e.strerror))
		continue
	if data == 'listening':
		l = len(text)
		logging.info('Sending %d bytes to %s' % (len(text), addr))
		conn.send(str(l))
		if not conn.recv(1024) == 'OK':
			conn.close()
			continue
		while text:
			conn.send(text[:100])
			text = text[100:]
		conn.close()
	else:
		conn.close()
		continue

