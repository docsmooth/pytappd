#!/usr/bin/env python
gVers = "0.2"

import os, sys, re, warnings, operator, datetime, socket, io, copy, argparse

##################################################################################
#
# Configuration Globals
#
##################################################################################

gAuthconfig="auth.ini"
gBaseUrl="https://api.untappd.com/v4"
logsep="\t"

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

# We're going to try to support both python2 and python3. We'll start
# by assuming python3, then trying to import a required module with the
# version 3 name.  If that fails, we'll try with the version 2 name
# Because we're already in a try/except without another try
# this import will either crash with a stack trace, or set
# the python version to 2.  We'll use that in places where we ask
# for user input using input() or raw_input() among others
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
# (this doesn't take the variable above, because I took it from another script
# wher it was fully tested already.
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
gMultiple=None
gOptions=None

class pytappdObject(object):
    def __init__(self, name):
        global gSession
        self.s=gSession
        self.r=None
        self.result=False
        self.baseurl=gBaseUrl
        self.data=None
        self.params=None
        self.actions={
                #"json":self.json,
                #"feed":self.checkins,
                #"info":self.info,
                "auth":self.auth,
                }

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
        self.help='''
The beer object (TBD)
        '''

class brewery(pytappdObject):
    def __init__(self, name):
        pytappdObject.__init__(self,name)
        self.help='''
The brewery object (TBD)
        '''

class user(pytappdObject):
    def __init__(self, name):
        pytappdObject.__init__(self,name)
        self.help='''
The user object (TBD)
        '''

def do(objtype, **kwargs):
    printdebug(objtype.name, "dispatching action: {0}".format(kwargs["act"]))
    printdebug(objtype.name, "passing arguments: {0}".format(kwargs))
    action=kwargs["act"]
    printdebug(objtype.name, "running self.actions[{0}], which is: {1}".format(action, objtype.actions[action]))
    return objtype.actions[action]()

def runUntappd(self, argv=None):
    global gOptions
    parser=argparse.ArgumentParser(description="Untappd Python CLI client")
    parser.add_argument("-m" "--multiple",
            action="store_true",
            default=False,
            help="Try to run the same thing/action on lots of input?",
            )
    parser.add_argument("-b", "--beer",
            type=str,
            help="Name or ID of the beer in question.",
            )
    parser.add_argument("-u", "--user",
            type=str,
            help="Name or ID of user (friend to check in, maybe?)",
            )
    parser.add_argument("-w", "--brewery",
            type=str,
            help="Name or ID of brewery to search.",
            )
    parser.add_argument("-l", "--location",
            type=int,
            help="Foursquare/Swarm location ID (Name lookup not implemented.)",
            )
    parser.add_argument("-t", "--thing",
            type=str,
            help="The thing to work with (beer, user, location)",
            )
    parser.add_argument("-a", "--action",
            type=str,
            help="The thing to do on the thing (search, lookup, check in)",
            )
    parser.add_argument("-v", "--loglevel",
            default=0,
            action="count",
            help="How Verbose to make the program (0-5)",
            )
    parser.add_argument("-c", "--config",
            type=str,
            help="Auth Configuration INI file.",
            default=gAuthconfig,
            )
    parser.add_argument("-f", "--filter",
            type=str,
            help="regex to filter log output against.",
            default="",
            )
    gOptions=parser.parse_args(argv)

    authconfig=None
    if gPythonv==3:
        authconfig=configparser.ConfigParser()
    elif gPythonv==2:
        authconfig=ConfigParser.ConfigParser()
    authconfig.read(gOptions.config)
    mything=""
    if gOptions.thing in gTypes:
        mything=gTypes[gOptions.thing]
    elif gOptions.thing in [ "help", "h", "?" ]:
        print("Valid API classes / things:")
        print("    Type this:".ljust(24, " ") + "= To get this Class")
        print("".ljust(43, "-"))
        for mything in sorted(gTypes.items(), key=operator.itemgetter(1)):
        #for mything in gClasses.items():
            #print("    " + mything[0].ljust(20, " ") + "= " + gClasses[mything[0]])
            print("    {}= {}".format(mything[0].ljust(20, " "), gTypes[mything[0]]))
        sys.exit(1)
    else:
        printerror("main", "invalid thing requested. Use -t help for a full list")
        sys.exit(2)
    untappd=None
    printdebug("main", "Trying to launch thing: {0}".format(mything))
    untappd=gClasses.get(mything, False)(mything)

    #untappd can come back as false, so that we can do help statements below
    if untappd:
        printdebug("main", str(untappd))

    if gOptions.action in untappd.actions:
        #action=pbps.actions[gOptions.action]
        # don't need to map this - the dispatch is smarter than that
        printdebug("main", "found action {0} for type {1}".format(gOptions.action, gOptions.thing))
    elif gOptions.action in [ "help", "h", "?" ]:
        print("Valid Actions for API class: {0}".format(mything))
        for action in untappd.actions:
            print("    " + action )
        print("       " + untappd.help)
        print("Use '-t {0} -a <action> --show' for a list of required arguments for each action.".format(mything))
        sys.exit(2)
    else:
        printerror("main", "invalid action '{0}' for type {1}".format(gOptions.action, mything))
        sys.exit(2)

    if gOptions.multiple:
        if gOptions.file:
            gMultiple=open(gOptions.file)

        headerline=gMultiple.readline().replace('\r', "")
        headerline=headerline.replace('\n', "")
        fields=headerline.split(logsep)
        printdebug("main", "Found {0} fields: {1}".format(len(fields), headerline))
        line=gMultiple.readline()
        printheader=True
        while line!="":
            line = line.replace('\r', "")
            line = line.replace('\n', "")
            printinfo("main", "Now reading line: {0}".format(line))
            parts=line.split(logsep)
            untappd=gClasses.get(mything)(mything)
            try:
                for i in range(len(fields)):
                    if (not hasattr(gOptions, fields[i])) or (not getattr(gOptions, fields[i], False)):
                        untappd.reqdata[fields[i]]=parts[i]
                        printverbose("main", "Setting field {0} to value {1}.".format(fields[i], parts[i]))
                    else:
                        printinfo("main", "Overriding {0} from file with {1}.".format(fields[i], getattr(gOptions, fields[i])))
            except IndexError:
                printerror("main", "Field mismatch - there are too few fields in the line: ")
                printerror("main", line)
                printerror("main", "Expected {0} fields.".format(len(fields)))
                sys.exit(4)
            untappd.printheader=printheader
            do(untappd, act=gOptions.action)
            line=gMultiple.readline()
            printheader=False  #this will disable printing headers in the rest of the objects we print out, so that an easier report can be saved

    else:
        do(untappd, act=gOptions.action)

    printdebug("main", str(untappd))
    untappd.signAppout()
    printverbose("main", "Now we are done.")
    if 200<=untappd.result<300:
        untappd.result=0
        #change 200 status codes to 0 for unix safe exiting
    sys.exit(pbps.result)


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
    if gOptions.filter:
        result = re.search(gOptions.filter, host + " " + line)
        if result:
            printline(prefix + logsep + host + logsep + line)
    else:
        printline(prefix + logsep + host + logsep + line)

def printerror(host, line):
    prefix = "ERROR   "
    if gOptions.loglevel >= 1:
        printerr(prefix, host, line)

def printwarn(host, line):
    prefix = "WARN    "
    if gOptions.loglevel >= 2:
        printerr(prefix, host, line)

def printinfo(host, line):
    prefix = "INFO    "
    if gOptions.loglevel >= 3:
        printerr(prefix, host, line)

def printverbose(host, line):
    prefix = "VERBOSE "
    if gOptions.loglevel >= 4:
        printerr(prefix, host, line)

def printdebug(host, line):
    prefix = "DEBUG   "
    if gOptions.loglevel >= 5:
        printerr(prefix, host, line)

# add each class here, both in case-insensitive (for the user) and case-sensitive (for the program) formats, as below:
#    "commandline": className,
#    "className": className,
# if you get an error:
#     pbps=gPBPSClasses.get(mything, False)(mything)
# TypeError: 'bool' object is not callable
# Then you didn't include the 2nd case-sensitive line
gClasses={
        "beer": beer,
        "user": user,
        "brewery": brewery,
        }
gTypes={}
for k,v in gClasses.items():
    gTypes[k] = v.__name__

if __name__ == "__main__":
    import sys
    if not sys.stdin.isatty():
        gMultiple=sys.stdin
        gOptions.multiple=True
    runUntappd(sys.argv)
