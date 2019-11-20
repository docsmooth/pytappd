#!/usr/bin/env python
"""Untappd python CLI tool

This script allows manipulating Untappd as yourself via the CLI
So you can drink beer and program and never touch your mouse.

Or phone.
"""
gVers = "0.4"

import os, sys, re, warnings, operator, datetime, socket, io, copy, argparse, logging
from urllib.parse import urlparse
from collections import defaultdict

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
logging.basicConfig(level=logging.DEBUG)
try:
    import requests
except ImportError:
    logging.critical("ERROR: You need to install the python requests library to use this tool!")
    logging.critical("ERROR: You can get it with either: ")
    logging.critical("ERROR:   yum -y install python35-pip; pip install requests")
    logging.critical("ERROR:   yum -y install python-requests")
    logging.critical("ERROR: or your specific OS's package management system.")
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
    #because configparser got renamed to lowercase in python3, we can
    # use it as a hint to the version of python in use. Then when other
    # imports or functions have different names, we can use this global
    # to know which method to call, like for input() vs raw_input()
    import ConfigParser
    gPythonv=2

# because Python 2.x uses "socket.error" and Python 3.x uses BrokenPipeError
# We have to variablize the expected error states so that we can properly
# catch pipe breaks in the print code throughout the script.
# in other words, if we drop python 2.x support, remove this code,
# then do :%s/brokenpipeerror/BrokenPipeError/g
# (this doesn't utilize the variable above, because I took it from
# another script where it was fully tested already.
import socket
try:
    brokenpipeerror = BrokenPipeError
except NameError:
    brokenpipeerror = IOError

# assume we're interactive until we discover otherwise
gInteractive=True


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
    logging.critical("ERROR: Can't set up decoder errors!")
    sys.exit(2)

gSession=requests.Session()
gMultiple=None
gOptions=None
gRedirectURL="https://www.totalnetsolutions.net/pytappd/callback"

class authObject(object):
    def __init__(self, config=gAuthconfig):
        if gPythonv==2:
            super(authObject, self).__init__()
        else:
            super().__init__()
        logging.debug("authObject: Initializing {0}".format(config))
        self.authconfig=None
        self.authenticated=False
        self.id=0
        self.token=None
        self.name=config
        if gPythonv==3:
            logging.debug("authObject: Python3 config parsing...")
            self.authconfig=configparser.ConfigParser()
        elif gPythonv==2:
            logging.debug("authObject: Python2 config parsing...")
            self.authconfig=ConfigParser.ConfigParser()
        self.authconfig.read(config)
        if "Authorization" in self.authconfig:
            logging.debug("authObject: Found Authorization section")
            if self.authconfig["Authorization"]["clientid"]:
                self.authconfig["Authorization"]["clientid"]=self.authconfig["Authorization"]["clientid"].strip('"')
                self.authconfig["Authorization"]["clientid"]=self.authconfig["Authorization"]["clientid"].strip("'")
                logging.info("authObject: Set Clientid to {0}".format(self.authconfig["Authorization"]["clientid"]))
                self.id=self.authconfig["Authorization"]["clientid"]
            if self.authconfig["Authorization"].get( "token", False):
                self.authconfig["Authorization"]["token"]=self.authconfig["Authorization"]["token"].strip('"')
                self.authconfig["Authorization"]["token"]=self.authconfig["Authorization"]["token"].strip("'")
                logging.info("authObject: Set Token to {0}".format(self.authconfig["Authorization"]["token"]))
                self.token=self.authconfig["Authorization"]["token"]
                self.authenticated=True
            elif self.authconfig["Authorization"].get("access_token", False):
                self.authconfig["Authorization"]["access_token"]=self.authconfig["Authorization"]["access_token"].strip('"')
                self.authconfig["Authorization"]["access_token"]=self.authconfig["Authorization"]["access_token"].strip("'")
                logging.info("authObject: Set Token to {0}".format(self.authconfig["Authorization"]["access_token"]))
                self.token=self.authconfig["Authorization"]["access_token"]
                self.authenticated=True
            logging.debug("authObject: Initialization complete, have id: {0}, and token {1}".format(self.id, self.token))
        else:
            logging.warning("authObject: No Authorization section found, does the file {0} exist?!")
        if not self.token:
            self.auth()

    def auth(self):
        logging.debug("auth: Need to authenticate online...")
        baseurl="https://untappd.com/oauth"
        printline("Please visit the following URL in your brower.  Paste the response URL below:")
        printline("{0}/authenticate/?client_id={1}&response_type=token&redirect_url={2}".format(baseurl, self.id, requests.utils.quote(gRedirectURL)))
        response_url=""
        while response_url == "":
            if gPythonv==2:
                try:
                    response_url=raw_input("Response URL: ")
                except SyntaxError:
                    response_url=""
                    #Python2 raises "SyntaxError: unexpected EOF while parsing" if you enter a blank value for input()
                except KeyboardInterrupt:
                    #cheater way of handling keyboard interrupts, instead of installing signal handlers at the top.
                    sys.exit(1)
            elif gPythonv==3:
                try:
                    response_url=input("Response URL: ")
                except SyntaxError:
                    response_url=""
                    #Python2 raises "SyntaxError: unexpected EOF while parsing" if you enter a blank value for input()
                except KeyboardInterrupt:
                    #cheater way of handling keyboard interrupts, instead of installing signal handlers at the top.
                    sys.exit(1)
        logging.debug("auth: attempting to pull fragment from {0}".format(response_url))
        parts=urlparse(response_url)
        blah, self.token=parts.fragment.split("=")
        if not self.token:
            logging.error("auth: Failed to get an access token from: {0}".format(response_url))
            return False
        result=self.save()
        if not result:
            logging.warning("auth: Failed to save auth file: {0}".format(self.name))
        logging.info("auth: Found access token: {0}".format(self.token))
        return True

    def save(self, **kwargs):
        logging.info("authObject: Saving configuration as new file.")
        configfile=self.name
        if kwargs.get("config", False):
            logging.info("authObject: Overriding file to: {0}".format(kwargs["config"]))
            configfile=kwargs["config"]
        if self.token:
            logging.info("authObject: storing access token: {0}".format(self.token))
            self.authconfig["Authorization"]["Access_Token"]=self.token
        if self.id:
            logging.info("authObject: storing Client ID: {0}".format(self.id))
            self.authconfig["Authorization"]["ClientID"]=self.id
        with open(configfile, 'w') as filename:
            result=self.authconfig.write(filename)
        return result


    def default(self, configfile):
        logging.info("authObject: Writing new auth object!")
        self.authconfig["Authorization"]["ClientID"]="dummy"
        result=self.save(configfile)
        return result

class dotappd(object):
    """This object uses an AuthObject to connect to the Untappd
    network to do its work.  It can do generic lookups and return
    that json to pytappdObject constructors.

    It will default to the ID and name of the logged in user, and custruct
    that user object for later reference.

    2019-11-16 Rob is thinking we'll need something similar for
    foursquare lookups when we get to that point.
    """
    def __init__(self, name=""):
        """I don't know what I'm doing with this initiator for dotappd
        Yet, but I know I need to write documentation.
        """
        if gPythonv==2:
            super(dotappd, self).__init__()
        else:
            super().__init__()
        global gSession
        self.s=gSession
        self.name = name
        self.id = 0
        self.r = None
        self.result = False
        self.baseurl = gBaseUrl
        self.data = None
        self.params={}
        self.authObject = None
        self.responses={
                "code":0,
                "error": "",
                "error_type":"",
                "friendly":"",
                }

    @property
    def json(self):
        try:
            return self.__json
        except:
            if getattr(self,"r", None) is not None:
                try:
                    return self.r.json()
                except ValueError:
                    return self.r.text()

    @json.setter
    def json(self, json=None):
        if json==None:
            try:
                self.__json=copy.deepcopy(self.r.json())
                # not going to validate if the HTTP we got back is valid data structure, cause I trust Greg
            except AttributeError:
                logging.error("JSON not initialized from HTTP and none passed in, what happened?")
                raise AttributeError
        else:
            self.__json=copy.deepcopy(json)

    def unsetJson(self):
        self.__json = None


    @property
    def id(self):
        try:
            return self.__id
        except AttributeError:
            return 0

    @id.setter
    def id(self, x=0):
        """Setting an ID on an online object means that we have to look it up.
        If we have to look it up, the return values should definitely be
        blank, so empty those out when we set the ID
        """
        self.result=False
        if self.id != 0 and self.id != x:
            # if self.id is 0, then we're just initializing, don't do extra work.
            self.unsetJson
        self.__id = x

    def callApi(self, method, verb="GET", params={}, **kwargs):
        """Make any arbitrary call to the Untappd API using the requests library.

        Keyword Arguments:
        method = the Untappd method to call (subpath of the URL)
        verb = the HTTP verb to make the call with, defaults to 'GET'
        params = the HTTP querystring parameters to append.

        This is abstracted from requests, so that we can standardize
        authentication and status checking specific to Untappd.

        """
        self.result=False
        if not self.authObject:
            logging.debug("callapi: Don't have an authentication object at all, initializing self.authObject.")
            self.authObject=authObject()
        if not self.params.get("access_token", False):
            logging.debug("callapi: Don't have an access token, adding from self.authObject {0}".format(self.authObject.token))
            self.params.update({"access_token": self.authObject.token})
        logging.debug("callapi: Entering with verb {0}".format(verb))
        url="{0}/{1}/".format(self.baseurl, method)
        if verb=="GET":
            logging.debug("callapi: GET {0} with params {1}".format(url, self.params))
            self.r=self.s.get(url, params=self.params)
        elif verb=="POST":
            logging.debug("callapi: POST {0} with params {1}".format(url, self,params))
            self.r=self.s.post(url, params=self.params)
        elif verb=="PUT":
            logging.debug("callapi: PUT {0} with params {1}".format(url, self,params))
            self.r=self.s.put(url, params=self.params)
        self.saveresponses()
        if self.r.status_code== requests.codes.ok:
            logging.debug("callapi: requests says our status code {0} is ok.".format(self.r.status_code))
            self.result=True
        else:
            logging.warning("callapi: Requests didn't like our status code {0}.".format(self.r.status_code))
            logging.error("callapi: {0}: {1}".format(self.r.status_code, self.responses["friendly"]))
            logging.info("callapi: {0}".format( self.responses["error_type"]))
            logging.info("callapi: {0}".format(self.responses["error"]))
            logging.debug("callapi: {0}".format(self.r.history))
            logging.debug("callapi: {0}".format(self.r.url))
            if self.r.headers.get("X-Ratelimit-Limit", False) and self.r.headers.get("X-Ratelimit-Remaining", False):
                logging.debug("callapi: Rate limit: {0}, remaining: {1}".format(self.r.headers["X-Ratelimit-Limit"], self.r.headers["X-Ratelimit-Remaining"]))
        return self.r.json()

    def saveresponses(self):
        logging.debug("saveResponse: Trying to save self.r status codes.")
        if self.r is not None:
            self.responses["code"]=self.r.status_code
            logging.debug("saveResponse: Code: {0}".format(self.responses["code"]))
            logging.debug("saveResponse: JSON: {0}".format(self.r.text))
            if self.r.status_code == 200:
                logging.info("saveResponse: No Error, exiting saveResponses.")
            else:
                try:
                    self.responses["error"]=self.r.json()["meta"]["error_detail"]
                    self.responses["error_type"]=self.r.json()["meta"]["error_type"]
                    self.responses["friendly"]=self.r.json()["meta"]["developer_friendly"]
                except JSONDecodeError:
                    logging.info("saveResponse: No JSON returned, only: {0}".format(self.r.text))
        if self.responses["friendly"] is "" and self.r.text:
            self.responses["friendly"] = self.r.text
        logging.debug("saveResponse: Error: {0}".format(self.responses["error"]))
        logging.debug("saveResponse: Type: {0}".format(self.responses["error_type"]))
        logging.debug("saveResponse: Friendly: {0}".format(self.responses["friendly"]))

class pytappdObject(object):
    def __init__(self, name="", json={}):
        '''all pytappd Objects can be initialized empty, or from a dict from r.json()["response"][thing]
        '''
        if gPythonv==2:
            super(pytappdObject, self).__init__()
        else:
            super().__init__()
        self.apiName="user"
        self.name = name
        self.id=0
        self.result=False
        self.printheader=True
        self.params={}
        self.responses={
                "code":0,
                "error": "",
                "error_type":"",
                "friendly":"",
                }
        self.headers=[
                ]
        self.fields=[
                ]
        if json!={}:
            self.json=json

    @property
    def json(self):
        try:
            return self.__json
        except:
            if getattr(self,"r", None) is not None:
                try:
                    return self.r.json()
                except ValueError:
                    return self.r.text()

    @json.setter
    def json(self, json=None):
        if json==None:
            logging.info("{0}: JSON not initialized from HTTP and none passed in, unsetting self.".format(self.name))
            self.id=0
            self.name=""
            self.__json=None
        else:
            #validate, then set
            if json.get("response"):
                logging.info("we got back the FULL json from an API call, so we have to de-nest the {0} object.".format(self.apiName))
                searchdict=json["response"][self.apiName]
            else:
                searchdict=json
            #logging.debug("Now looking through object {0}".format(searchdict))
            for field in self.fields:
                logging.debug("Looking up field {0} in json object.".format(field))
                if searchdict.get(field, None) is None:
                    # got a stub from somewhere else, so set as blank
                    logging.info("{0}: JSON not valid for this object type, missing field {1}".format(self.name, field))
                    searchdict[field]=None
                if re.search('id$', field, re.I):
                    self.id=searchdict[field]
                    logging.info("found an ID field {0}, setting as ID: {1}".format(field, searchdict[field]))
                elif re.search(self.apiName + '.*name$', field, re.I):
                    self.name=searchdict[field]
                    logging.info("found a name field {0}, setting as: {1}".format(field, searchdict[field]))
                else:
                    logging.debug("Field {0} is not name or id.".format(field))
            self.__json=copy.deepcopy(searchdict)
            #self.__dict__=self.__json

    def unsetJson(self):
        self.__json = None


    @property
    def id(self):
        try:
            return self.__id
        except AttributeError:
            self.__id=0
            return 0

    @id.setter
    def id(self, x=0):
        logging.debug("Setting id for {0} to {1}".format(self.apiName, x))
        if x==0:
            self.unsetJson()
            self.__id=0
        else:
            self.__id=x

    @property
    def name(self):
        return self.__name

    @name.setter
    def name(self,x=""):
        logging.debug("Setting name for {0} to {1}".format(self.apiName, x))
        try:
            if x=="":
                self.unsetJson()
        except AttributeError:
            self.unsetJson()
        self.__name=str(x)

    @property
    def vals(self):
        melist=[]
        if self.json:
            for field in self.fields:
                #logging.debug("vals: Trying to find {0} in self.json.".format(field))
                try:
                    if type(self.json[field]) != dict:
                        melist.append(str(self.json[field]))
                        #logging.debug("vals: Found {0}".format(self.json[field]))
                    else:
                        melist.append("{}")
                except KeyError:
                    melist.append("Null")
        return melist

    def __eq__(self, other):
        try:
            if self.id == other.id and self.name == other.name:
                return True
            return False
        except AttributeError:
            return False
        return False

    def __iter__(self):
        self.__iterCount=0
        return self

    def __next__(self):
        index=self.__iterCount
        self.__iterCount+=1
        try:
            return self.vals[index]
        except IndexError:
            raise StopIteration

    def __str__(self):
        global logsep
        mestring=""
        if self.json:
            mestring=logsep.join(str(self.vals))
        return mestring

    def __int__(self):
        return int(self.id)

    def __long__(self):
        return long(self.id)

    def __nonzero__(self):
        return self.__bool__()

    def __bool__(self):
        if getattr(self,"id", 0) == 0:
            return False
        elif getattr(self,"name", "") == "":
            return False
        return True

    def __index__(self):
        return self.id

    def __len__(self):
        if self:
            return len(self.headers)
        return 0


#########################################################################################################################################################
#########################################################################################################################################################
#########################################################################################################################################################
#########################################################################################################################################################
# END OF PARENT CLASS
#########################################################################################################################################################
#########################################################################################################################################################
#########################################################################################################################################################
#########################################################################################################################################################

class beer(pytappdObject):
    """Beer!

    Each beer in Untappd has a name, an ID, and a brewery it came from.
    It may have a list of checkins nearby, a list of locations nearby, and other
    variable information, but the name and ID we can trust.
    """
    def __init__(self, name="", json={}):
        """As of 0.4 this is initialized from json because someone
        looked up a beer."""
        if gPythonv==2:
            super(beer, self).__init__()
        else:
            super().__init__()
        self.apiName="beer"
        self.headers=[
                "ID",
                "Name",
                "Style",
                "Brewery Name",
                "Brewery ID",
                "Rating",
                "Rating Count",
                "In Production",
                "Slug",
                "Homebrew?",
                "Created",
                "Ratings",
                "Score",
                "Stats",
                "Brewery",
                "Auth Rating",
                "Wish List?",
                "Media",
                "Similar",
                "Friends",
                "Vintages",
                ]
        self.fields=[
                "bid",
                "beer_name",
                "beer_label",
                "beer_abv",
                "beer_ibu",
                "beer_description",
                "beer_style",
                "is_in_production",
                "beer_slug",
                "is_homebrew",
                "created_at",
                "rating_count",
                "rating_score",
                "stats",
                "brewery",
                "auth_rating",
                "wish_list",
                "media",
                "similar",
                "friends",
                "vintages",
                ]
        self.paths={
                "info": {
                    "method": "GET",
                    "path": "beer/info/",
                    "send": int(),
                    },
                "search": {
                    "method":"GET",
                    "path": "search/beer/",
                    "send":str(),
                    }
                }
        if json=={}:
            logging.debug("Init {0} object empty.".format(self.apiName))
            self.__name=name
            self.brewery=brewery()
        else:
            logging.debug("Init {0} object from json.".format(self.apiName))
            self.json=json
            if self.json.get("brewery", False):
                # User activity feed has brewery not underneath the beer itself.
                self.brewery=brewery(json=self.json["brewery"])

class brewery(pytappdObject):
    '''
The brewery object (TBD)
    '''
    def __init__(self, name=None, json={}):
        if gPythonv==2:
            super(brewery, self).__init__()
        else:
            super().__init__()
        self.apiName="brewery"
        self.headers=[
                "ID",
                "Name",
                "Slug",
                "Label",
                "Country",
                "In Production?",
                "Independant?",
                "Claimed?",
                "Beers",
                "Contact"
                "Type",
                "TypeID",
                "Rating",
                "Description",
                "Stats",
                "Owners",
                "Media",
                "Beer List",
                ]
        self.fields=[
                "brewery_id",
                "brewery_name",
                "brewery_slug",
                "brewery_label",
                "country_name",
                "brewery_in_production",
                "is_independant",
                "claimed_status",
                "beer_count",
                "contact",
                "brewery_type",
                "brewery_type_id",
                "rating",
                "brewery_description",
                "stats",
                "owners",
                "media",
                "beer_list",
                ]
        self.paths={
                "info": {
                    "method": "GET",
                    "path": "brewery/info/",
                    "send": int(),
                    },
                "search": {
                    "method":"GET",
                    "path": "search/brewery/",
                    "send":str(),
                    }
                }
        if json=={}:
            logging.debug("Init {0} object empty.".format(self.apiName))
            self.__name=name
        else:
            logging.debug("Init {0} object from json.".format(self.apiName))
            self.json=json

class user(pytappdObject):
    def __init__(self, name):
        if gPythonv==2:
            super(user, self).__init__()
        else:
            super().__init__()
        self.help='''
The user object (TBD)
        '''

def do(objtype, **kwargs):
    logging.debug("dispatching action: {0}".format(kwargs["act"]))
    logging.debug("passing arguments: {0}".format(kwargs))
    action=kwargs["act"]
    logging.debug("running self.actions[{0}], which is: {1}".format(action, objtype.actions[action]))
    return objtype.actions[action]

def runUntappd(self, argv=None):
    global gOptions, gMultiple, gloglevel
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

    if gOptions.loglevel<=1:
        logging.setLevel(logging.CRITICAL)
    elif gOptions.loglevel<=2:
        logging.setLevel(logging.ERROR)
    elif gOptions.loglevel<=3:
        logging.setLevel(logging.WARNING)
    elif gOptions.loglevel<=4:
        logging.setLevel(logging.INFO)
    elif gOptions.loglevel<=5:
        logging.setLevel(logging.DEBUG)


    config=authObject()
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
        logging.error("invalid thing requested. Use -t help for a full list")
        sys.exit(2)
    untappd=None
    logging.debug("Trying to launch thing: {0}".format(mything))
    untappd=gClasses.get(mything, False)(mything)

    #untappd can come back as false, so that we can do help statements below
    if untappd:
        logging.debug(str(untappd))
        #attach the configuration/authentication to the object we're using
        untappd.auth=config

    if gOptions.action in untappd.actions:
        #action=pbps.actions[gOptions.action]
        # don't need to map this - the dispatch is smarter than that
        logging.debug("found action {0} for type {1}".format(gOptions.action, gOptions.thing))
    elif gOptions.action in [ "help", "h", "?" ]:
        print("Valid Actions for API class: {0}".format(mything))
        for action in untappd.actions:
            print("    " + action )
        print("       " + untappd.help)
        print("Use '-t {0} -a <action> --show' for a list of required arguments for each action.".format(mything))
        sys.exit(2)
    else:
        logging.error("invalid action '{0}' for type {1}".format(gOptions.action, mything))
        sys.exit(2)

    if gMultiple:
        if gOptions.file:
            gMultiple=open(gOptions.file)

        headerline=gMultiple.readline().replace('\r', "")
        headerline=headerline.replace('\n', "")
        fields=headerline.split(logsep)
        logging.debug("{0} fields: {1}".format(len(fields), headerline))
        line=gMultiple.readline()
        printheader=True
        while line!="":
            line = line.replace('\r', "")
            line = line.replace('\n', "")
            logging.info("reading line: {0}".format(line))
            parts=line.split(logsep)
            untappd=gClasses.get(mything)(mything)
            try:
                for i in range(len(fields)):
                    if (not hasattr(gOptions, fields[i])) or (not getattr(gOptions, fields[i], False)):
                        untappd.reqdata[fields[i]]=parts[i]
                        logging.info("field {0} to value {1}.".format(fields[i], parts[i]))
                    else:
                        logging.info("{0} from file with {1}.".format(fields[i], getattr(gOptions, fields[i])))
            except IndexError:
                logging.error("mismatch - there are too few fields in the line: ")
                logging.error(line)
                logging.error("Expected {0} fields.".format(len(fields)))
                sys.exit(4)
            untappd.printheader=printheader
            do(untappd, act=gOptions.action)
            line=gMultiple.readline()
            printheader=False  #this will disable printing headers in the rest of the objects we print out, so that an easier report can be saved

    else:
        do(untappd, act=gOptions.action)

    logging.debug(str(untappd))
    #untappd.signAppout()
    logging.info("we are done.")
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

'''
Testing notes:
import pytappd
ac=pytappd.authObject("./auth.ini")
x=pytappd.dotappd("docsmooth")
x.authObject=ac
b=pytappd.beer(json=x.callApi(method="beer/info/3839"))
for x in b:
    print(str(x))
'''
