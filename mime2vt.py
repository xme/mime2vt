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
		try:
			response['@timestamp'] = time.strftime("%Y-%m-%dT%H:%M:%S+01:00")
			res = es.index(index=config['esIndex'], doc_type="VTresult", body=json.dumps(response))
		except:
			writeLog("Cannot index to Elasticsearch")
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
		fp = open(os.path.join(args.directory, f), 'wb')
		fp.write(data)
		fp.close()
		md5 = hashlib.md5(data).hexdigest()
		writeLog("DEBUG: Extracted MD5 %s from Zip" % md5)
		vt = VirusTotalPublicApi(config['apiKey'])
		response = vt.get_file_report(md5)
		writeLog("DEBUG: VT Response recevied")

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
		logging.basicConfig()
		es = Elasticsearch([config['esServer']])

	# Read the mail flow from STDIN
	data = "" . join(sys.stdin)
	msg = email.message_from_string(data)

	if args.dump_file:
		try:
			fp = open(args.dump_file, 'a')
		except OSError as e:
			writeLog('Cannot dump message to %s: %s' % (args.dump_file, e.errno))
		fp.write(data)
		fp.close()

	# Process MIME parts
	for part in msg.walk():
		data = part.get_payload(None, True)
		if data:
			md5 = hashlib.md5(data).hexdigest()
			contenttype = part.get_content_type()

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
						try:
							response['@timestamp'] = time.strftime("%Y-%m-%dT%H:%M:%S+01:00")
							res = es.index(index=config['esIndex'], doc_type="VTresult", body=json.dumps(response))
						except:
							writeLog("Cannot index to Elasticsearch")

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
