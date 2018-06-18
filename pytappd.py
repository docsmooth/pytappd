#!/usr/bin/env python
gVers = "0.1"

import os, sys, re, warnings, operator, datetime, socket, io, copy, argparse

##################################################################################
#
# Configuration Globals
#
##################################################################################

gAuthconfig="auth.ini"
gBaseUrl="https://api.untappd.com/v4"

##################################################################################
#
# End user Configuration Below Here
#
##################################################################################

try:
    import requests
except ImportError:
    print("ERROR: You need to install the python requests library to use this tool!")
    print("ERROR: You can get it with either: ")
    print("ERROR:   yum -y install python35-pip; pip install requests")
    print("ERROR:   yum -y install python-requests")
    print("ERROR: or your specific OS's package management system.")
    sys.exit(2)

gPythonv=3
try:
    import configparser
except ImportError:
    import ConfigParser
    gPythonv=2
    #now we can use this if we want to ask for input, and can ask the right way.

# because Python 2.x uses "socket.error" and Python 3.x uses BrokenPipeError
# We have to variablize the expected error states so that we can properly
# catch pipe breaks in the print code throughout the script.
# in other words, if we drop python 2.x support, remove this code,
# then do :%s/brokenpipeerror/BrokenPipeError/g
import socket
try:
    brokenpipeerror = BrokenPipeError
except NameError:
    brokenpipeerror = IOError

gInteractive=True
if not (sys.stdout.isatty() and sys.stdin.isatty()):
    #Are in some kind of pipeline, so disabling interactive input.
    gInteractive=False

from collections import defaultdict

# disable HTTPS Insecure warnings, because they'll have already set a flag saying they want to ignore.
requests.packages.urllib3.disable_warnings()
try:
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    from requests.packages.urllib3.exceptions import SubjectAltNameWarning
    from requests.packages.urllib3.exceptions import SecurityWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    requests.packages.urllib3.disable_warnings(SubjectAltNameWarning)
    requests.packages.urllib3.disable_warnings(SecurityWarning)
except ImportError:
    if gInteractive:
        print("WARNING: Your version of requests includes an older urllib3. If you are using '-i' you will still get warnings. (This will not print in scripts.)")

gSession=requests.Session()

class pytappdObject(object):
    def __init__(self, name):
        self.s=gSession
        self.r=None
        self.result=False
        self.baseurl=gBaseUrl
        self.data=None
        self.params=None
        self.actions={
                "json":self.json,
                "feed":self.checkins,
                "info":self.info,
                "auth":self.auth,
                }
        if gPythonv==3:
            authconfig=configparser.ConfigParser()
        elif gPythonv==2:
            authconfig=ConfigParser.ConfigParser()
        authconfig.read(gAuthconfig)

    def responses(self):
        self.responses.code=0
        self.responses.error="None"
        self.responses.error_type="None"
        self.responses.friendly="None"
        if self.r:
            self.responses.code=self.r.json("code")
            self.responses.error=self.r.json("error_detail")
            self.responses.error_type=self.r.json("error_type")
            self.responses.friendly=self.r.json("developer_friendly")

    def auth(self):
        pass


class test(pytappdObject):
    def __init__(self, name):
        pytappdObject.__init__(self, name)
        self.actions.update({
            "test": self.test,
            }
            )
        self.id = None
        self.help = '''
Test module - verifies that the API is available on the endpoint you're using.
list: Will report success even if the usernmame/password is wrong.
signAppin: will report success only if username/key are right.


'''

    def test(self, **kwargs):
        if self.signAppin(**kwargs):
            return True

class beer(pytappdObject):
    def __init__(self, name):
        pytappdObject.__init__(self,name)

class brewery(pytappdObject):
    def __init__(self, name):
        pytappdObject.__init__(self,name)

class user(pytappdObject):
    def __init__(self, name):
        pytappdObject.__init__(self,name)

def runUntappd(self):
    mytype=""
    if options.type in gPBPStypes:
        mytype=gPBPStypes[options.type]
    elif options.type in [ "help", "h", "?" ]:
        print("Valid API classes / types:")
        print("    Type this:".ljust(24, " ") + "= To get this Class")
        print("".ljust(43, "-"))
        for mytype in sorted(gPBPStypes.items(), key=operator.itemgetter(1)):
            print("    " + mytype[0].ljust(20, " ") + "= " + gPBPStypes[mytype[0]])
        sys.exit(1)
    else:
        printerror("main", "invalid type requested. Use -t help for a full list")
        sys.exit(2)
    pbps=None
    printdebug("main", "Trying to launch type: {0}".format(mytype))
    pbps=gPBPSClasses.get(mytype, False)(mytype)

    #pbps can come back as false, so that we can do help statements below
    if pbps:
        printdebug("main", str(pbps))

    if options.action in pbps.actions:
        #action=pbps.actions[options.action]
        # don't need to map this - the dispatch is smarter than that
        printdebug("main", "found action " + options.action + " for type " + options.type)
    elif options.action in [ "help", "h", "?" ]:
        print("Valid Actions for API class: " + mytype)
        for action in pbps.actions:
            print("    " + action )
        print("       " + pbps.help)
        print("Use '-t {0} -a <action> --show' for a list of required arguments for each action.".format(mytype))
        sys.exit(2)
    else:
        printerror("main", "invalid action '" + options.action + "' for type " + mytype)
        sys.exit(2)


def striplist(l):
    y=[x.lstrip() for x in l]
    return([x.strip() for x in y])

def printline(line):
    line = line.strip()
    try:
        sys.stdout.write(line + "\n")
    except brokenpipeerror:
        sys.exit(32)

def printerr(prefix, host, line):
    global logsep
    line = line.strip()
    if options.filter:
        result = re.search(options.filter, host + " " + line)
        if result:
            printline(prefix + logsep + host + logsep + line)
    else:
        printline(prefix + logsep + host + logsep + line)

def printerror(host, line):
    prefix = "ERROR   "
    if options.loglevel >= 1:
        printerr(prefix, host, line)

def printwarn(host, line):
    prefix = "WARN    "
    if options.loglevel >= 2:
        printerr(prefix, host, line)

def printinfo(host, line):
    prefix = "INFO    "
    if options.loglevel >= 3:
        printerr(prefix, host, line)

def printverbose(host, line):
    prefix = "VERBOSE "
    if options.loglevel >= 4:
        printerr(prefix, host, line)

def printdebug(host, line):
    prefix = "DEBUG   "
    if options.loglevel >= 5:
        printerr(prefix, host, line)

# add each class here, both in case-insensitive (for the user) and case-sensitive (for the program) formats, as below:
#    "commandline": className,
#    "className": className,
# if you get an error:
#     pbps=gPBPSClasses.get(mytype, False)(mytype)
# TypeError: 'bool' object is not callable
# Then you didn't include the 2nd case-sensitive line
gClasses={
        "beer": beer,
        "user": user,
        "brewery": brewery,
        }
gTypes={}

if __name__ == "__main__":
    import sys
    runUntappd(sys.argv)
    for k,v in gClasses.items():
        gTypes[k] = v.__name__
