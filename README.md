mime2vt.py
==========
Unpack MIME attachments from a file/stdin and check them against virustotal.com

Usage
-----
mime2vt.py [-h] [-d DIRECTORY] [-v] [-c CONFIG]

Unpack MIME attachments from a file and check them against virustotal.com

optional arguments:
  -h, --help            show this help message and exit
  -d DIRECTORY, --directory DIRECTORY
                        directory where files will be extracted (default:
                        /tmp)
  -v, --verbose         verbose output
  -c CONFIG, --config CONFIG
                        configuration file (default: /etc/mime2vt.conf)

Todo
----
* 
