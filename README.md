mime2vt.py
==========
Unpack MIME attachments from STDIN and check them against virustotal.com
Use it indepently:

cat /tmp/mail.dump | mime2vt -c /etc/mime2vt.conf

Or via tools like Procmail:

<pre>
:0
* ^X-Spam-Flag: YES
{
        :0c
        | /usr/local/bin/mime2vt.py -d /tmp/mime -c /home/xavier/.mime2vt.conf
	:0
	spam
}
</pre>

Usage
-----
<pre>
mime2vt.py [-h] [-d DIRECTORY] [-v] [-c CONFIG]

Unpack MIME attachments from a file and check them against virustotal.com

optional arguments:
-h, --help            show this help message and exit
-d DIRECTORY, --directory DIRECTORY
                      directory where files will be extracted (default: /tmp)
-v, --verbose         verbose output
-c CONFIG, --config CONFIG
                      configuration file (default: /etc/mime2vt.conf)
</pre>

Results
-------
Information is sent via Syslog:

Dec 12 18:41:20 marge mime2vt.py[1104]: Processing zip archive: 4359ae6078390f417ab0d4411527a5c2.zip
Dec 12 18:41:21 marge mime2vt.py[1104]: File: VOICE748-348736.scr (acb05e95d713b1772fb96a5e607d539f) Score: 38/53 Scanned: 2014-11-13 15:45:04 (29 days, 2:56:17)

Requirements
----
<pre>
sudo pip install python-dateutil
sudo pip install elasticsearch
sudo pip install virustotal-api    
</pre>

Todo
----
* 
