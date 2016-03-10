#!/usr/bin/env python
#
# mime2vt.py - Submit MIME attachments to VirusTotal
#
# Author: Xavier Mertens <xavier@rootshell.be>
# Copyright: GPLv3 (http://gplv3.fsf.org/)
# Feel free to use the code, but please share the changes you've made
# 

import argparse
import ConfigParser
import email
import errno
import hashlib
import json
import logging
import mimetypes
import os
import re
import sys
import time
import zipfile
import sqlite3
import syslog
from elasticsearch import Elasticsearch
from virus_total_apis import PublicApi as VirusTotalPublicApi
from optparse import OptionParser
from datetime import datetime
from dateutil import parser
import pyzmail

# Try to use oletools
try:
	from oletools.olevba import VBA_Parser, TYPE_OLE, TYPE_OpenXML, TYPE_Word2003_XML, TYPE_MHTML
	useOLETools = 1
except:
	useOLETools = 0

args = ''

# Default configuration 
config = {
	'apiKey': '',
	'esServer': '',
	'esIndex': 'virustotal',
	'dbPath': '/var/tmp/mime2vt.db'
}


def timeDiff(t):

	"""Compute the delta between two timestamps"""

	fmt = '%Y-%m-%d %H:%M:%S'
	now = time.strftime(fmt)
	return datetime.strptime(now, fmt) - datetime.strptime(t, fmt)

def writeLog(msg):
	syslog.openlog(logoption=syslog.LOG_PID,facility=syslog.LOG_MAIL)
	syslog.syslog(msg)
	return

def dbCreate():

	"""Create the SQLite DB at first run"""

	if (not os.path.isfile(config['dbPath'])):
		db = sqlite3.connect(config['dbPath'])
		cursor = db.cursor()
		cursor.execute('''
			CREATE TABLE files(md5 TEXT PRIMARY KEY, filename TEXT, created DATETIME DEFAULT CURRENT_TIMESTAMP)
			''')
		cursor.execute('''
			CREATE TABLE urls(url TEXT)
			''')
		db.commit()
		db.close()
	return

def dbMD5Exists(md5):
	""" Search for a MD5 hash in the database"""
	""" (Return "1" if found) """
	if not md5:
		return 1

	try:
		db = sqlite3.connect(config['dbPath'])
	except:
		writeLog("Cannot open the database file (locked?)")
		return 0
	cursor = db.cursor()
	cursor.execute('''SELECT md5 FROM files WHERE md5=?''', (md5,))
	if cursor.fetchone():
		db.close()
		return 1
	db.close()
	return 0

def dbAddMD5(md5, filename):
	""" Store a new MD5 hash in the database """
	if not md5 or not filename:
		return 0
	try:
		db = sqlite3.connect(config['dbPath'])
	except:
		writeLog("Cannot open the database file (locked?)")
		return 0
	cursor = db.cursor()
	cursor.execute('''INSERT INTO files(md5,filename) VALUES(?,?)''', (md5,filename,))
	db.commit()
	db.close()
	writeLog("DEBUG: dbAddMD5: %s" % md5)
	return 0

def submit2vt(filename):

	"""Submit a new file to VT for scanning"""

	# Check VT score
	vt = VirusTotalPublicApi(config['apiKey'])
	response = vt.scan_file(filename)

	# DEBUG
	fp = open('/tmp/vt.debug', 'a')
	fp.write(json.dumps(response, sort_keys=False, indent=4))
	fp.close()

	if config['esServer']:
		# Save results to Elasticsearch
		try:
			response['@timestamp'] = time.strftime("%Y-%m-%dT%H:%M:%S+01:00")
			res = es.index(index=config['esIndex'], doc_type="VTresult", body=json.dumps(response))
		except:
			writeLog("Cannot index to Elasticsearch")
	return

def generateDumpDirectory(path):

	"""Generate the destination directory to dump files"""

	# Prepare the output directory:
	# %m -> month
	# %d -> day
	# %y -> year
	t_day   = time.strftime("%d")
	t_month = time.strftime("%m")
	t_year  = time.strftime("%Y")
	path = path.replace('%d', t_day)
	path = path.replace('%m', t_month)
	path = path.replace('%y', t_year)
	try:
		os.makedirs(path)
		writeLog("DEBUG: Generated directory: %s" % path)
	except OSError as e:
		# Ignore directory exists error
		if e.errno != errno.EEXIST:
			raise
		else:
			return(path)

	# Fix corrext access rights on the direcrity (just for me)
	try:
		writeLog("DEBUG: chmod() on %s" % path)
		os.chmod(path, 0775)
	except IOError as e:
		writeLog("DEBUG: chmod() failed on %s: %s" % (path,e.strerror))
		raise

	return(path)

def parseOLEDocument(f):
	"""Parse an OLE document for VBA macros"""
	if not f or not useOLETools:
		return

	writeLog('DEBUG: Analyzing with oletools')
	try:
		v = VBA_Parser(f)
	except:
		writeLog("Not a supported file format: %s" % f)
		return
	writeLog('DEBUG: Detected file type: %s' % v.type)

	# Hack: Search for a .js extension
	fname, fextension = os.path.splitext(f)
	writeLog("DEBUG (parseOLE): Found extension == %s (%s)" % (fextension,f))

	if v.detect_vba_macros() or fextension == ".js":
		writeLog('DEBUG: VBA Macros/JScript found')
		try:
			t = open("%s.analysis" % f, 'w')
		except IOError as e:
			writeLog("Cannot create analysis file %s.analysis: %s" % (f,e.strerror))
			return
		for kw_type, keyword, description in v.analyze_macros():
			t.write("%-12s | %-25s | %s\n" % (kw_type, keyword, description))
		t.close()
		writeLog("DEBUG: Analysis dumped to %s.analysis" % f)
	else:
		writeLog('DEBUG: No VBA Macros found')
	return

def processZipFile(filename):

	"""Extract files from a ZIP archive and test them against VT"""

	zf = zipfile.ZipFile(filename)
	for f in zf.namelist():
		try:
			data = zf.read(f)
		except KeyError:
			writeLog("Cannot extract %s from zip file %s" % (f, filename))
			return
		fp = open(os.path.join(generateDumpDirectory(args.directory), f), 'wb')
		fp.write(data)
		fp.close()
		md5 = hashlib.md5(data).hexdigest()
		if dbMD5Exists(md5):
			writeLog("DEBUG: MD5 %s exists" % md5)
			continue

		writeLog("DEBUG: Extracted MD5 %s from Zip" % md5)
		vt = VirusTotalPublicApi(config['apiKey'])
		response = vt.get_file_report(md5)
		writeLog("DEBUG: VT Response received")

		if config['esServer']:
			# Save results to Elasticsearch
			try:
				response['@timestamp'] = time.strftime("%Y-%m-%dT%H:%M:%S+01:00")
				res = es.index(index=config['esIndex'], doc_type="VTresult", body=json.dumps(response))
			except:
				writeLog("Cannot index to Elasticsearch")
		writeLog("DEBUG: Step1")

		# DEBUG
		fp = open('/tmp/vt.debug', 'a')
		fp.write(json.dumps(response, sort_keys=False, indent=4))
		fp.close()
		writeLog("DEBUG: Step1: %s" % response['results']['response_code'])

		if response['response_code'] == 200:
			if response['results']['response_code']:
				positives = response['results']['positives']
				total = response['results']['total']
				scan_date = response['results']['scan_date']

				writeLog('File: %s (%s) Score: %s/%s Scanned: %s (%s)' %
					(f, md5, positives, total, scan_date, timeDiff(scan_date)))
			else:
				submit2vt(os.path.join(generateDumpDirectory(args.directory), f))
				writeLog('File: %s (%s) not found, submited for scanning' %
					(f, md5))
			dbAddMD5(md5,f)
		else:
			writeLog('VT Error: %s' % response['error'])

		# Analyze OLE documents if API is available
		parseOLEDocument(os.path.join(generateDumpDirectory(args.directory), f))
	return

def parseMailheaders(data):

	"""Extract useful e-mail headers"""

	if data:
		msg=pyzmail.PyzMessage.factory(data)

		mailheaders = { "subject": msg.get_subject(),
						"from": msg.get_address('from'),
						"to": msg.get_addresses('to'),
						"cc": msg.get_addresses('cc'),
						"x-mailer": msg.get('x-mailer', ''),
						"date": msg.get('date', ''),
						"message-id": msg.get('message-id', ''),
						"user-agent": msg.get('user-agent',''),
						"x-virus-scanned": msg.get('x-virus-scanned',''),
						"return-path": msg.get('return-path','')
						}

		received = msg.get('received','')
		if received:
			ip = re.findall( r'[0-9]+(?:\.[0-9]+){3}', received )
			if ip:
				mailheaders["ip"] = ip
		return mailheaders
	else:
		return None

def main():
	global args
	global config
	global es
	global verbose

	parser = argparse.ArgumentParser(
		description = 'Unpack MIME attachments from a file and check them against virustotal.com')
	parser.add_argument('-d', '--directory',
		dest = 'directory',
		help = 'directory where files will be extracted (default: /tmp) %%d,%%m,%%y can use used for dynamic names',
		metavar = 'DIRECTORY')
	parser.add_argument('-v', '--verbose',
		action = 'store_false',
		dest = 'verbose',
		help = 'verbose output',
		default = False)
	parser.add_argument('-c', '--config',
		dest = 'config_file',
		help = 'configuration file (default: /etc/mime2vt.conf)',
		metavar = 'CONFIG')
	parser.add_argument('-l', '--log',
		dest = 'dump_file',
		help = 'mail dump file (default /tmp/message.dump)',
		metavar = 'DUMPFILE')
	args = parser.parse_args()

	# Default values
	if not args.directory:
		args.directory = '/tmp'
	if not args.config_file:
		args.config_file = '/etc/mime2vt.conf'

	#writeLog('DEBUG: config_file = %s' % args.config_file)

	try:
		c = ConfigParser.ConfigParser()
		c.read(args.config_file)
		config['apiKey'] = c.get('virustotal', 'apikey')
		excludetypes = c.get('virustotal', 'exclude').split(',')
		# Elasticsearch config
		config['esServer'] = c.get('elasticsearch', 'server')
		config['esIndex'] = c.get('elasticsearch', 'index')
		config['dbPath'] = c.get('database', 'dbpath')
	except OSError as e:
		writeLog('Cannot read config file %s: %s' % (args.config_file, e.errno))
		exit

	if config['esServer']:
		logging.basicConfig()
		es = Elasticsearch([config['esServer']])

	# Create the SQLite DB
	dbCreate()

	# Read the mail flow from STDIN
	data = "" . join(sys.stdin)
	msg = email.message_from_string(data)
	mailheaders = parseMailheaders(data)

	if args.dump_file:
		try:
			fp = open(args.dump_file, 'a')
		except OSError as e:
			writeLog('Cannot dump message to %s: %s' % (args.dump_file, e.errno))
		fp.write(data)
		fp.close()

	# Process MIME parts
	for part in msg.walk():
		contenttype = part.get_content_type()
		filename = part.get_param('name')

		# Hack: Search for a .js extension
		try:
			fname, fextension = os.path.splitext(filename)
		except:
			fextension = "none"

		data = part.get_payload(None, True)
		if data:
			md5 = hashlib.md5(data).hexdigest()
			if dbMD5Exists(md5):
				writeLog("Skipping existing MD5 %s" % md5)
				continue

			# New: Extract URLS
			if contenttype in [ 'text/html', 'text/plain' ]:
				urls = []
				# Source: https://gist.github.com/uogbuji/705383
				GRUBER_URLINTEXT_PAT = re.compile(ur'(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:\'".,<>?\xab\xbb\u201c\u201d\u2018\u2019]))')
				lines = data.split('\n')
				for line in lines:
					try:
						#urls.append(re.search("(?P<url>https?://[^\s]+)", word).group("url"))
						for url in GRUBER_URLINTEXT_PAT.findall(line):
							if url[0]:
								urls.append(url[0])
					except:
						pass
				fp = open('/var/tmp/urls.log', 'a')
				for url in urls:
					fp.write("%s\n" % url)
				fp.close()

			# Process only interesting files
			# if contenttype not in ('text/plain', 'text/html', 'image/jpeg', 'image/gif', 'image/png'):
			if contenttype not in excludetypes or fextension == '.js':
				if not filename:
					filename = md5
				mime_ext = mimetypes.guess_extension(contenttype)
				if not mime_ext:
					# Use a generic bag-of-bits extension
					mime_ext = '.bin'
				f_name, f_ext = os.path.splitext(filename)
				if not f_ext:
					filename += mime_ext

				writeLog('Found interesting file: %s (%s)' % (filename, contenttype))

				fp = open(os.path.join(generateDumpDirectory(args.directory), filename), 'wb')
				fp.write(data)
				fp.close()

				if contenttype in ['application/zip', 'application/x-zip-compressed']:
					# Process ZIP archive
					writeLog('Processing zip archive: %s' % filename)
					processZipFile(os.path.join(generateDumpDirectory(args.directory), filename))
				else:
					# Check VT score
					vt = VirusTotalPublicApi(config['apiKey'])
					response = vt.get_file_report(md5)

					# Save results to Elasticsearch
					if config['esServer']:
						try:
							response['@timestamp'] = time.strftime("%Y-%m-%dT%H:%M:%S+01:00")
							response['filename'] = filename
							response['mail'] = mailheaders							
							res = es.index(index=config['esIndex'], doc_type="VTresult", body=json.dumps(response))
						except:
							writeLog("Cannot index to Elasticsearch")

					# DEBUG
					fp = open('/tmp/vt.debug', 'a')
					fp.write(json.dumps(response, sort_keys=False, indent=4))
					fp.close()

					if response['response_code'] == 200:
						if response['results']['response_code']:
							positives = response['results']['positives']
							total = response['results']['total']
							scan_date = response['results']['scan_date']

							writeLog('File: %s (%s) Score: %s/%s Scanned: %s (%s)' %
								(filename, md5, positives, total, scan_date, timeDiff(scan_date)))
						else:
							submit2vt(os.path.join(generateDumpDirectory(args.directory), filename))
							writeLog('File: %s (%s) not found, submited for scanning' %
								(filename, md5))
						dbAddMD5(md5,filename)
					else:
						writeLog('VT Error: %s' % response['error'])

					# Analyze OLE documents if API is available
					parseOLEDocument(os.path.join(generateDumpDirectory(args.directory), filename))

if __name__ == '__main__':
    main()
