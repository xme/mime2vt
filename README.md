mime2vt.py
==========
Unpack MIME attachments from STDIN and check them against virustotal.com
Use it indepently:

cat /tmp/mail.dump | mime2vt -c /etc/mime2vt.conf

Or via tools like Procmail:

:0
* ^X-Spam-Flag: YES
\{
        :0c
        | /usr/local/bin/mime2vt.py -d /tmp/mime -c /home/xavier/.mime2vt.conf
	:0
	spam
\}

Usage
-----
mime2vt.py [-h] [-d DIRECTORY] [-v] [-c CONFIG]

Unpack MIME attachments from a file and check them against virustotal.com

optional arguments:
 -h, --help            show this help message and exit
 -d DIRECTORY, --directory DIRECTORY
                       directory where files will be extracted (default: /tmp)
 -v, --verbose         verbose output
 -c CONFIG, --config CONFIG
                       configuration file (default: /etc/mime2vt.conf)

Todo
----
* 
