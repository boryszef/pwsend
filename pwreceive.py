#!/usr/bin/python2

from cryptography.fernet import Fernet
import socket
import sys
import os
import stat
import time
import posix


server_name = '192.168.1.129'
server_port = 1666
debug = 0
secretKey = 'Rlpa0MfJ1WSflCNCFgfWU9s3c5FZa57Me3x2afLwBTc='
cutHereText = "-----CUT_HERE-----"



def get_passwd():
    foo = [x.split(':') for x in open('/etc/passwd').readlines()]
    passwd = []
    users = []
    for line in foo:
        pid = int(line[2])
        if pid < 1000 or pid >= 65000:
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
    passwd = []
    users = []
    for line in foo:
        pid = int(line[2])
        if pid < 1000:
            passwd.append(':'.join(map(lambda x: x.strip(), line))+'\n')
            users.append(line[0].strip())
    text = ''.join(passwd)
    return text, users


t = int(socket.gethostname().split('-')[1])*2
if debug:
	print >>sys.stderr, "Waiting %d seconds, to avoid concurent connections." % (t)
time.sleep(t)

engine = Fernet(secretKey)

soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
soc.connect((server_name, server_port))

soc.send('listening')
data = soc.recv(1024)
l = int(data)
if debug:
	print >>sys.stderr, "Expecting %d bytes of data." % (l)
soc.send('OK')

ciphtext = ''
data = soc.recv(1024)
while data:
	ciphtext += data
	data = soc.recv(1024)
if debug:
	print >>sys.stderr, "Received:\n%s" % (ciphtext)

rl = len(ciphtext)
if rl != l:
	print >>sys.stderr, "Wrong length, %d != %d" % (rl, l)
	sys.exit(1)
soc.close()
text = ciphtext.split(cutHereText)
if len(text) != 3:
	print >>sys.stderr, "Incomplete data!"
	exit(1)

passwd = engine.decrypt(text[0])
shadow = engine.decrypt(text[1])
group = engine.decrypt(text[2])

if debug:
	print >>sys.stderr, "'passwd' data:\n%s" % (passwd)
	print >>sys.stderr, "'shadow' data:\n%s" % (shadow)
	print >>sys.stderr, "'group' data:\n%s" % (group)

# Backup of passwd
file = open('/etc/passwd').read()
bak = open('/etc/passwd.pwrec','w')
os.chmod('/etc/passwd.pwrec',0600)
bak.write(file)
bak.close()
#os.remove(bak.name)

# Backup of shadow
file = open('/etc/shadow').read()
bak = open('/etc/shadow.pwrec','w')
os.chmod('/etc/shadow.pwrec',0600)
bak.write(file)
bak.close()
#os.remove(bak.name)

# Backup of group
file = open('/etc/group').read()
bak = open('/etc/group.pwrec','w')
os.chmod('/etc/group.pwrec',0600)
bak.write(file)
bak.close()
#os.remove(bak.name)

old_passwd, users = get_passwd()
if debug:
	print >>sys.stderr, "Old records from 'passwd', that will be preserved:"
	print >>sys.stderr, old_passwd

old_shadow = get_shadow(users)
if debug:
	print >>sys.stderr, "Old records from 'shadow', that will be preserved:"
	print >>sys.stderr, old_shadow

old_group, grps = get_group()
if debug:
	print >>sys.stderr, "Old records from 'group', that will be preserved:"
	print >>sys.stderr, old_group

file = open('/etc/passwd', 'w')
file.write(old_passwd)
file.write(passwd)
file.close()
if debug:
	print >>sys.stderr, "New 'passwd' written."

attr = stat.S_IRUSR|stat.S_IWUSR|stat.S_IRGRP|stat.S_IROTH
os.chmod('/etc/passwd', attr)
if debug:
	print >>sys.stderr, "Fixed permissions on 'passwd'."

file = open('/etc/shadow', 'w')
file.write(old_shadow)
file.write(shadow)
file.close()
if debug:
	print >>sys.stderr, "New 'passwd' written."

attr = stat.S_IRUSR|stat.S_IWUSR
os.chmod('/etc/shadow', attr)
if debug:
	print >>sys.stderr, "Fixed permissions on 'shadow'."

file = open('/etc/group', 'w')
file.write(old_group)
file.write(group)
file.close()
if debug:
	print >>sys.stderr, "New 'group' written."

attr = stat.S_IRUSR|stat.S_IWUSR|stat.S_IRGRP|stat.S_IROTH
os.chmod('/etc/group', attr)
if debug:
	print >>sys.stderr, "Fixed permissions on 'group'."


