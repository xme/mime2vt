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
import mimetypes
import os
import sys
import time
import zipfile
import syslog
from elasticsearch import Elasticsearch
from virus_total_apis import PublicApi as VirusTotalPublicApi
from optparse import OptionParser
from datetime import datetime
from dateutil import parser

args = ''

# Default configuration 
config = {
	'apiKey': '',
	'esServer': '',
	'esIndex': 'virustotal'
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
		response['@timestamp'] = time.strftime("%Y-%m-%dT%H:%M:%S+01:00")
		res = es.index(index=config['esIndex'], doc_type="VTresult", body=json.dumps(response))

	return

def processZipFile(filename):

	"""Extract files from a ZIP archive and test them against VT"""

	zf = zipfile.ZipFile(filename)
	for f in zf.namelist():
		try:
			data = zf.read(f)
		except KeyError:
			print "Cannot extract %s from zip file %s" % (f, filename)
			return
		fp = open(os.path.join(args.directory, f), 'wb')
		fp.write(data)
		fp.close()
		md5 = hashlib.md5(data).hexdigest()
		vt = VirusTotalPublicApi(config['apiKey'])
		response = vt.get_file_report(md5)

		if config['esServer']:
			# Save results to Elasticsearch
			response['@timestamp'] = time.strftime("%Y-%m-%dT%H:%M:%S+01:00")
			res = es.index(index=config['esIndex'], doc_type="VTresult", body=json.dumps(response))

		# DEBUG
		fp = open('/tmp/vt.debug', 'a')
		fp.write(json.dumps(response, sort_keys=False, indent=4))
		fp.close()

		if response['results']['response_code']:
			positives = response['results']['positives']
			total = response['results']['total']
			scan_date = response['results']['scan_date']

			writeLog('File: %s (%s) Score: %s/%s Scanned: %s (%s)' %
				(f, md5, positives, total, scan_date, timeDiff(scan_date)))
		else:
			submit2vt(os.path.join(args.directory, f))
			writeLog('File: %s (%s) not found, submited for scanning' %
				(f, md5))
	return

def main():
	global args
	global config
	global es
	global verbose

	parser = argparse.ArgumentParser(
		description = 'Unpack MIME attachments from a file and check them against virustotal.com')
	parser.add_argument('-d', '--directory',
		dest = 'directory',
		help = 'directory where files will be extracted (default: /tmp)',
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
	args = parser.parse_args()

	# Default values
	if not args.directory:
		args.directory = '/tmp'
	if not args.config_file:
		args.config_file = '/etc/mime2vt.conf'

	try:
		c = ConfigParser.ConfigParser()
		c.read(args.config_file)
		config['apiKey'] = c.get('virustotal', 'apikey')
		excludetypes = c.get('virustotal', 'exclude').split(',')
		# Elasticsearch config
		config['esServer'] = c.get('elasticsearch', 'server')
		config['esIndex'] = c.get('elasticsearch', 'index')
	except OSError as e:
		writeLog('Cannot read config file %s: %s' % (args.config_file, e.errno))
		exit

	try:
		os.mkdir(args.directory)
	except OSError as e:
		# Ignore directory exists error
		if e.errno != errno.EEXIST:
			raise

	if config['esServer']:
		print "DEBUG: using elk"
		es = Elasticsearch([config['esServer']])

	# Read the mail flow from STDIN
	data = "" . join(sys.stdin)
	msg = email.message_from_string(data)

	# Process MIME parts
	for part in msg.walk():
		data = part.get_payload(None, True)
		if data:
			md5 = hashlib.md5(data).hexdigest()
			contenttype = part.get_content_type()

			# Process only interesting files
			# if contenttype not in ('text/plain', 'text/html', 'image/jpeg', 'image/gif', 'image/png'):
			if contenttype not in excludetypes:
				filename = part.get_filename()
				if not filename:
					filename = md5
				ext = mimetypes.guess_extension(contenttype)
				if not ext:
					# Use a generic bag-of-bits extension
					ext = '.bin'
				filename = '%s%s' % (md5, ext)

				fp = open(os.path.join(args.directory, filename), 'wb')
				fp.write(data)
				fp.close()

				if contenttype == 'application/zip':
					# Process ZIP archive
					writeLog('Processing zip archive: %s' % filename)
					processZipFile(os.path.join(args.directory, filename))
				else:
					# Check VT score
					vt = VirusTotalPublicApi(config['apiKey'])
					response = vt.get_file_report(md5)

					# Save results to Elasticsearch
					if config['esServer']:
						response['@timestamp'] = time.strftime("%Y-%m-%dT%H:%M:%S+01:00")
						res = es.index(index=config['esIndex'], doc_type="VTresult", body=json.dumps(response))

					# DEBUG
					fp = open('/tmp/vt.debug', 'a')
					fp.write(json.dumps(response, sort_keys=False, indent=4))
					fp.close()

					if response['results']['response_code']:
						positives = response['results']['positives']
						total = response['results']['total']
						scan_date = response['results']['scan_date']

						writeLog('File: %s (%s) Score: %s/%s Scanned: %s (%s)' %
							(filename, md5, positives, total, scan_date, timeDiff(scan_date)))
					else:
						submit2vt(os.path.join(args.directory, filename))
						writeLog('File: %s (%s) not found, submited for scanning' %
							(filename, md5))
						

if __name__ == '__main__':
    main()
