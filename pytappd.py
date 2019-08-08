#!/usr/bin/env python
gVers = "0.3"

import os, sys, re, warnings, operator, datetime, socket, io, copy, argparse
from urllib.parse import urlparse

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

try:
    from simplejson.errors import JSONDecodeError
except ImportError:
    print("ERROR: Can't set up decoder errors!")
    sys.exit(2)

gSession=requests.Session()
gMultiple=None
gOptions=None
gRedirectURL="https://www.totalnetsolutions.net/pytappd/callback"

class authObject(object):
    def __init__(self, config):
        printdebug("authObject", "Initializing {0}".format(config))
        self.authconfig=None
        self.authenticated=False
        self.id=0
        self.token=None
        self.name=config
        if gPythonv==3:
            printdebug("authObject", "Python3 config parsing...")
            self.authconfig=configparser.ConfigParser()
        elif gPythonv==2:
            printdebug("authObject", "Python2 config parsing...")
            self.authconfig=ConfigParser.ConfigParser()
        self.authconfig.read(config)
        if "Authorization" in self.authconfig:
            printdebug("authObject", "Found Authorization section")
            if self.authconfig["Authorization"]["clientid"]:
                self.authconfig["Authorization"]["clientid"]=self.authconfig["Authorization"]["clientid"].strip('"')
                self.authconfig["Authorization"]["clientid"]=self.authconfig["Authorization"]["clientid"].strip("'")
                printverbose("authObject", "Set Clientid to {0}".format(self.authconfig["Authorization"]["clientid"]))
                self.id=self.authconfig["Authorization"]["clientid"]
            if self.authconfig["Authorization"].get("token", False):
                self.authconfig["Authorization"]["token"]=self.authconfig["Authorization"]["token"].strip('"')
                self.authconfig["Authorization"]["token"]=self.authconfig["Authorization"]["token"].strip("'")
                printverbose("authObject", "Set Token to {0}".format(self.authconfig["Authorization"]["token"]))
                self.token=self.authconfig["Authorization"]["token"]
                self.authenticated=True
            elif self.authconfig["Authorization"].get("Access_token", False):
                self.authconfig["Authorization"]["access_token"]=self.authconfig["Authorization"]["access_token"].strip('"')
                self.authconfig["Authorization"]["access_token"]=self.authconfig["Authorization"]["access_token"].strip("'")
                printverbose("authObject", "Set Token to {0}".format(self.authconfig["Authorization"]["access_token"]))
                self.token=self.authconfig["Authorization"]["access_token"]
                self.authenticated=True
            printdebug("authObject", "Initialization complete, have id: {0}, and token {1}".format(self.id, self.token))
        else:
            printwarn("authObject", "No Authorization section found, does the file {0} exist?!")


    def save(self, **kwargs):
        printinfo("authObject", "Saving configuration as new file.")
        configfile=self.name
        if kwargs.get("config", False):
            printinfo("authObject", "Overriding file to: {0}".format(kwargs["config"]))
            configfile=kwargs["config"]
        if self.token:
            printinfo("authObject", "storing access token: {0}".format(self.token))
            self.authconfig["Authorization"]["Access_Token"]=self.token
        if self.id:
            printinfo("authObject", "storing Client ID: {0}".format(self.id))
            self.authconfig["Authorization"]["ClientID"]=self.id
        with open(configfile, 'w') as filename:
            result=self.authconfig.write(filename)
        return result


    def default(self, configfile):
        printinfo("authObject", "Writing new auth object!")
        self.authconfig["Authorization"]["ClientID"]="dummy"
        result=self.save(configfile)
        return result



class pytappdObject(object):
    def __init__(self, name):
        global gSession
        self.s=gSession
        self.name = name
        self.id=0
        self.r=None
        self.result=False
        self.baseurl=gBaseUrl
        self.data=None
        self.printheader=True
        self.params={}
        self.authObject=None
        self.responses={
                "code":0,
                "error": "",
                "error_type":"",
                "friendly":"",
                }
        self.actions={
                "json":self.json,
                #"feed":self.checkins,
                #"info":self.info,
                "auth":self.auth,
                }
        self.headermap={
                "name":"Name",
                "id":"ID",
                }
        self.headers=[
                "Name",
                "ID",
                ]

    def vals(self):
        melist=[]
        if self.r:
            for field in self.header:
                try:
                    melist.append(self.r.json()[field])
                except KeyError:
                    melist.append("Null")
        return melist

    def __iter__(self):
        self.iterCount=0
        return self

    def __next__(self):
        index=self.iterCount
        self.iterCount+=1
        try:
            return self.headers[index]
        except IndexError:
            raise StopIteration

    def __str__(self):
        mestring=""
        if self.r:
            mestring=logsep.join(self.vals)
        return mestring


    def auth(self, auth=None):
        printdebug("auth", "Need to auth online, backing up baseurl...")
        if type(auth) != type(authObject):
            printinfo("auth", "Was passed an empty auth object, is normal at beginning of program, seeding with gOptions.")
            auth=authObject(gOptions.config)
        backupbaseurl=self.baseurl
        self.baseurl="https://untappd.com/oauth"
        self.params={
            "client_id":auth.id,
            "response_type":"token",
            "redirect_url":gRedirectURL,
            }
        printline("Please visit the following URL in your brower.  Paste the response URL below:")
        printline("{0}/authenticate/?client_id={1}&response_type=token&redirect_url={2}".format(self.baseurl, auth.id, requests.utils.quote(gRedirectURL)))
        response_url=""
        while response_url == "":
            if gPythonv==2:
                try:
                    response_url=raw_input("Response URL: ")
                except SyntaxError:
                    retvals[req]=""
                    #Python2 raises "SyntaxError: unexpected EOF while parsing" if you enter a blank value for input()
                except KeyboardInterrupt:
                    #cheater way of handling keyboard interrupts, instead of installing signal handlers at the top.
                    sys.exit(1)
            elif gPythonv==3:
                try:
                    response_url=input("Response URL: ")
                except SyntaxError:
                    retvals[req]=""
                    #Python2 raises "SyntaxError: unexpected EOF while parsing" if you enter a blank value for input()
                except KeyboardInterrupt:
                    #cheater way of handling keyboard interrupts, instead of installing signal handlers at the top.
                    sys.exit(1)
        printdebug("callapi", "attempting to pull fragment from {0}".format(response_url))
        parts=urlparse(response_url)
        blah, auth.token=parts.fragment.split("=")
        if not auth.token:
            printerror("auth", "Failed to get an access token from: {0}".format(response_url))
            return False
        self.params["access_token"]=auth.token
        self.authObject=auth
        result=auth.save()
        if not result:
            printwarn("auth", "Failed to save auth file: {0}".format(auth.name))
        printverbose("auth", "Found access token: {0}".format(auth.token))
        self.baseurl=backupbaseurl
        return True

    def callApi(self, verb, method):
        self.result=False
        if not self.authObject:
            self.auth()
        printdebug("callapi", "Entering with verb {0}".format(verb))
        url="{0}/{1}/".format(self.baseurl, method)
        if verb=="GET":
            printdebug("callapi", "GET {0} with params {1}".format(url, self.params))
            self.r=self.s.get(url, params=self.params)
        elif verb=="POST":
            printdebug("callapi", "POST {0} with params {1}".format(url, self,params))
            self.r=self.s.post(rul, params=self.params)
        elif verb=="PUT":
            printdebug("callapi", "PUT {0} with params {1}".format(url, self,params))
            self.r=self.s.put(rul, params=self.params)
        self.saveresponses()
        if self.r.status_code== requests.codes.ok:
            printdebug("callapi", "requests says our sattus code {0} is ok.".format(self.r.status_code))
            self.result=True
        else:
            printwarn("callapi", "Requests didn't like our status code {0}.".format(self.r.status_code))
            printerror("callapi", "{0}: {1}".format(self.r.status_code, self.responses["friendly"]))
            printverbose("callapi", self.responses["error_type"])
            printverbose("callapi", self.responses["error"])
            printdebug("callapi", "".format(self.r.history))
            printdebug("callapi", self.r.url)
            if self.r.headers.get("X-Ratelimit-Limit", False) and self.r.headers.get("X-Ratelimit-Remaining", False):
                printdebug("callapi", "Rate limit: {0}, remaining: {1}".format(self.r.headers["X-Ratelimit-Limit"], self.r.headers["X-Ratelimit-Remaining"]))
        return self.result

    def initFromJson(self, json):
        printdebug("jsonInit", "Entering...")
        #for key in self.header:
        #    self.get(key)=

    def json(self):
        if self.r is not None:
            if self.r.json():
                return self.r.json()
            else:
                return self.r.text
        else:
            return ""

    def saveresponses(self):
        printdebug("saveResponse", "Trying to save self.r status codes.")
        if self.r is not None:
            self.responses["code"]=self.r.status_code
            printdebug("saveResponse", "Code: {0}".format(self.responses["code"]))
            printdebug("saveResponse", "JSON: {0}".format(self.r.text))
            try:
                self.responses["error"]=self.r.json()["error_detail"]
                self.responses["error_type"]=self.r.json()["error_type"]
                self.responses["friendly"]=self.r.json()["developer_friendly"]
            except JSONDecodeError:
                printinfo("saveResponse", "No JSON returned, only: {0}".format(self.r.text))
        if self.responses["friendly"] is "" and self.r.text:
            self.responses["friendly"] = self.r.text
        printdebug("saveResponse", "Error: {0}".format(self.responses["error"]))
        printdebug("saveResponse", "Type: {0}".format(self.responses["error_type"]))
        printdebug("saveResponse", "Friendly: {0}".format(self.responses["friendly"]))

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
        self.brewery=brewery("null")
        self.help='''
The beer object (TBD)
        '''
        self.headermap={
                "bid":"id",
                "beer_name":"name",
                "beer_style":"style",
                "brewery_name":self.brewery.name,
                "brewery_id":self.brewery.id,
                }
        self.headers=[
                "ID",
                "Name",
                "Style",
                "Brewery Name",
                "Brewery ID",
                ]

class brewery(pytappdObject):
    def __init__(self, name):
        pytappdObject.__init__(self,name)
        self.help='''
The brewery object (TBD)
        '''
        self.header=[
                "brewery_id",
                "brewery_name",
                "brewery_type",
                "country_name",
                ]

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
    global gOptions, gMultiple
    parser=argparse.ArgumentParser(description="Untappd Python CLI client")
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
            default=1,
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

    config=authObject(gOptions.config)
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
            print("    {0}= {1}".format(mything[0].ljust(20, " "), gTypes[mything[0]]))
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

    if gMultiple:
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
    #untappd.signAppout()
    printverbose("main", "Now we are done.")
    if 200<=untappd.result<300:
        untappd.result=0
        #change 200 status codes to 0 for unix safe exiting
    sys.exit(untappd.result)


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
    if not (sys.stdout.isatty() and sys.stdin.isatty()):
        #Are in some kind of pipeline, so disabling interactive input.
        gInteractive=False
    if not sys.stdin.isatty():
        gMultiple=sys.stdin
        gOptions.multiple=True
    runUntappd(sys.argv)
