#!/usr/bin/env python
"""Untappd python CLI tool

This script allows manipulating Untappd as yourself via the CLI
So you can drink beer and program and never touch your mouse.

Or phone.
"""
gVers = "0.14"

import os, sys, re, warnings, operator, datetime, socket, io, copy, argparse, logging
from urllib.parse import urlparse
from collections import defaultdict
from cmd import Cmd

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
mylog=logging.getLogger("pytappd")
reqlog=logging.getLogger('requests.packages.urllib3')
logging.getLogger("urllib3").setLevel(logging.CRITICAL)
try:
    import requests
except ImportError:
    mylog.critical("ERROR: You need to install the python requests library to use this tool!")
    mylog.critical("ERROR: You can get it with either: ")
    mylog.critical("ERROR:   yum -y install python35-pip; pip install requests")
    mylog.critical("ERROR:   yum -y install python-requests")
    mylog.critical("ERROR:   pip install requests")
    mylog.critical("ERROR: or your specific OS's package management system.")
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
    mylog.critical("ERROR: Can't set up decoder errors!")
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
        mylog.debug("authObject: Initializing {0}".format(config))
        self.authconfig=None
        self.authenticated=False
        self.id=0
        self.token=None
        self.name=config
        if gPythonv==3:
            mylog.debug("authObject: Python3 config parsing...")
            self.authconfig=configparser.ConfigParser()
        elif gPythonv==2:
            mylog.debug("authObject: Python2 config parsing...")
            self.authconfig=ConfigParser.ConfigParser()
        self.authconfig.read(config)
        if "Authorization" in self.authconfig:
            mylog.debug("authObject: Found Authorization section")
            if self.authconfig["Authorization"]["clientid"]:
                self.authconfig["Authorization"]["clientid"]=self.authconfig["Authorization"]["clientid"].strip('"')
                self.authconfig["Authorization"]["clientid"]=self.authconfig["Authorization"]["clientid"].strip("'")
                mylog.info("authObject: Set Clientid to {0}".format(self.authconfig["Authorization"]["clientid"]))
                self.id=self.authconfig["Authorization"]["clientid"]
            if self.authconfig["Authorization"].get( "token", False):
                self.authconfig["Authorization"]["token"]=self.authconfig["Authorization"]["token"].strip('"')
                self.authconfig["Authorization"]["token"]=self.authconfig["Authorization"]["token"].strip("'")
                mylog.info("authObject: Set Token to {0}".format(self.authconfig["Authorization"]["token"]))
                self.token=self.authconfig["Authorization"]["token"]
                self.authenticated=True
            elif self.authconfig["Authorization"].get("access_token", False):
                self.authconfig["Authorization"]["access_token"]=self.authconfig["Authorization"]["access_token"].strip('"')
                self.authconfig["Authorization"]["access_token"]=self.authconfig["Authorization"]["access_token"].strip("'")
                mylog.info("authObject: Set Token to {0}".format(self.authconfig["Authorization"]["access_token"]))
                self.token=self.authconfig["Authorization"]["access_token"]
                self.authenticated=True
            mylog.info("authObject: Initialization complete, have id: {0}, and token {1}".format(self.id, self.token))
        else:
            mylog.warning("authObject: No Authorization section found, does the file {0} exist?!")
        if not self.token:
            self.auth()

    def auth(self):
        mylog.debug("auth: Need to authenticate online...")
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
        mylog.debug("auth: attempting to pull fragment from {0}".format(response_url))
        parts=urlparse(response_url)
        blah, self.token=parts.fragment.split("=")
        if not self.token:
            mylog.error("auth: Failed to get an access token from: {0}".format(response_url))
            return False
        result=self.save()
        if not result:
            mylog.warning("auth: Failed to save auth file: {0}".format(self.name))
        mylog.info("auth: Found access token: {0}".format(self.token))
        return True

    def save(self, **kwargs):
        mylog.info("authObject.save: Saving configuration as new file.")
        configfile=self.name
        if kwargs.get("config", False):
            mylog.info("authObject.save: Overriding file to: {0}".format(kwargs["config"]))
            configfile=kwargs["config"]
        if self.token:
            mylog.info("authObject.save: storing access token: {0}".format(self.token))
            self.authconfig["Authorization"]["Access_Token"]=self.token
        if self.id:
            mylog.info("authObject.save: storing Client ID: {0}".format(self.id))
            self.authconfig["Authorization"]["ClientID"]=self.id
        with open(configfile, 'w') as filename:
            result=self.authconfig.write(filename)
        return result


    def default(self, configfile):
        mylog.info("authObject.save: Writing new auth object!")
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
        self.data = {}
        self.params={}
        self.authObject = None
        self.responses={
                "code":0,
                "error": "",
                "error_type":"",
                "friendly":"",
                }
        self.paths={
                "beer": {
                    "info": {
                        "method": "GET",
                        "path": "beer/info/",
                        "func": self.getBeer,
                        },
                    "search": {
                        "method":"GET",
                        "path": "search/beer",
                        "func": self.searchbeer,
                        },
                    "user": {
                        "method": "GET",
                        "path": "user/beers/",
                        "func": False,
                        },
                    },
                "brewery": {
                    "info": {
                        "method": "GET",
                        "path": "brewery/info/",
                        "func": self.getBrewery,
                        },
                    "search": {
                        "method":"GET",
                        "path": "search/brewery/",
                        "func": self.searchbrewery,
                        },
                    },
                "actions": {
                    "checkin": {
                        "method": "POST",
                        "path": "checkin/add",
                        "send": dict(),
                        "func": self.checkin,
                        },
                    "toast": {
                        "method": "POST",
                        "path": "checkin/toast/",
                        "send": int(),
                        },
                    "comment": {
                        "method": "POST",
                        "path": "checkin/addcomment/",
                        "send": int(),
                        },
                    },
                "user": {
                    "info": {
                        "method": "GET",
                        "path": "user/info/",
                        "send": str(),
                        "func": self.getUser,
                        },
                    "beers": {
                        "method": "GET",
                        "path": "user/beers/",
                        "send": str(),
                        "func": self.getUserBeers,
                        },
                    "checkins": {
                        "method" : "GET",
                        "path": "user/checkins/",
                        "send" : str(),
                        "func": self.getCheckins,
                        },
                    },
                "checkin": {
                    "recent": {
                        "method" : "GET",
                        "path": "checkin/recent/",
                        "send" : str(),
                        "func": self.getCheckins,
                        },
                    },
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
                mylog.error("json.setter: JSON not initialized from HTTP and none passed in, what happened?")
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

    def __callApi(self, method, verb="GET", params={}, **kwargs):
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
            mylog.debug("callapi: Don't have an authentication object at all, initializing self.authObject.")
            self.authObject=authObject()
        if not self.params.get("access_token", False):
            mylog.debug("callapi: Don't have an access token, adding from self.authObject {0}".format(self.authObject.token))
            params.update({"access_token": self.authObject.token})
        mylog.debug("callapi: Entering with verb {0}".format(verb))
        url="{0}/{1}/".format(self.baseurl, method)
        params.update(self.params)
        if kwargs.get("limit", False):
            params["limit"]=kwargs["limit"]
        elif gOptions!=None and gOptions.limit:
            params["limit"]=gOptions.limit
        if kwargs.get("offset", False):
            params["offset"]=kwargs["offset"]
        elif gOptions!=None and gOptions.offset:
            params["offset"]=gOptions.offset
        if kwargs.get("sort", False):
            params["sort"]=kwargs["sort"]
        elif gOptions!=None and gOptions.sort:
            params["sort"]=gOptions.sort
        if kwargs.get("tz", False):
            self.data["timezone"]=tz
        else:
            self.data["timezone"]="CDT"
        if kwargs.get("shout", False):
            self.data["shout"]=kwargs["shout"]
        elif gOptions!=None and gOptions.shout:
            self.data["shout"]=gOptions.shout
        if kwargs.get("rating", False):
            self.data["rating"]=kwargs["rating"]
        elif gOptions!=None and gOptions.rating:
            self.data["rating"]=gOptions.rating
        if kwargs.get("twitter", False):
            self.data["twitter"]="on"
        elif gOptions!=None and gOptions.twitter:
            self.data["twitter"]="on"
        if kwargs.get("facebook", False):
            self.data["facebook"]="on"
        elif gOptions!=None and gOptions.facebook:
            self.data["facebook"]="on"
        if verb=="GET":
            mylog.debug("callapi: GET {0} with params {1}".format(url, params))
            self.r=self.s.get(url, params=params)
        elif verb=="POST":
            if self.data:
                mylog.debug("callapi: POST {0} with params {1} and data: {2}".format(url, params, self.data))
                self.r=self.s.post(url, params=params, data=self.data)
            else:
                mylog.debug("callapi: POST {0} with params {1}".format(url, params))
                self.r=self.s.post(url, params=params)
        elif verb=="PUT":
            mylog.debug("callapi: PUT {0} with params {1}".format(url, params))
            self.r=self.s.put(url, params=params)
        self.saveresponses()
        if self.r.status_code== requests.codes.ok:
            mylog.debug("callapi: requests says our status code {0} is ok.".format(self.r.status_code))
            self.result=True
        else:
            mylog.warning("callapi: Requests didn't like our status code {0}.".format(self.r.status_code))
            mylog.error("callapi: {0}: {1}".format(self.r.status_code, self.responses["friendly"]))
            mylog.info("callapi: {0}".format( self.responses["error_type"]))
            mylog.info("callapi: {0}".format(self.responses["error"]))
            mylog.debug("callapi: {0}".format(self.r.history))
            mylog.debug("callapi: {0}".format(self.r.url))
            if self.r.headers.get("X-Ratelimit-Limit", False) and self.r.headers.get("X-Ratelimit-Remaining", False):
                mylog.debug("callapi: Rate limit: {0}, remaining: {1}".format(self.r.headers["X-Ratelimit-Limit"], self.r.headers["X-Ratelimit-Remaining"]))
        return self.r.json()

    def __search(self, thing, val, offset=0, limit=50):
        '''abstraction for CallApi()
        Call as dotappd.cmd(thing="beer", what="search", val="Dogfish 60 Minute")
        '''
        mylog.debug("search: trying to do search on {0} with value: {1}".format(thing,val))
        verb=self.paths[thing]["search"]["method"]
        path=self.paths[thing]["search"]["path"]
        params={}
        if val:
            mylog.debug("search: adding '?q={0}' to URL.".format(val))
            params.update({"q":val})
        if offset:
            mylog.debug("search: setting offset to: {0}".format(offset))
            params.update({"offset":offset})
        if limit:
            mylog.debug("search: setting limit to: {0}".format(limit))
            params.update({"limit":limit})
        return self.__callApi(verb=verb, method=path, params=params)["response"]

    def checkin(self, val, **kwargs):
        mylog.debug("checkin: trying to check in beer: {0}".format(val))
        if not val:
            mylog.debug("checkin: no value {0}, looking in kwargs dict.".format(val))
            val=gOptions.beer
            mylog.debug("checkin: no value {0}, looking in kwargs dict.".format(val))
        mybeer=None
        verb=self.paths["actions"]["checkin"]["method"]
        path=self.paths["actions"]["checkin"]["path"]
        if (val.isdigit()):
            mylog.debug("checkin: Looking up beer by ID: {0}".format(val))
            myjson=self.getBeerJson(val)
            mybeer=beer(json=myjson)
        else:
            mylog.debug("checkin: Searching up beer by name: {0}".format(val))
            beerlist=self.searchbeer(val)
            mybeer=beerlist[0]
        date=datetime.datetime.now(datetime.timezone.utc).astimezone()
        utc_offset=date.utcoffset() / datetime.timedelta(seconds=1)
        utc_offset=utc_offset / 3600
        utc_offset=str(utc_offset)
        mylog.debug("checkin: Have UTC offset of {0} for date {1}".format(utc_offset, date))
        self.data={
                'timezone':"CDT",
                'shout':"",
                'gmt_offset':"-5",
                'rating':0,
                'bid':mybeer.id,
                }
        if kwargs.get("location", False) or (gOptions!=None and gOptions.location):
            #can only push to foursquare iwth a location
            mylog.debug("checkin: Have been asked to add a venue: {0}".format(kwargs.get("location", gOptions.location)))
            location=kwargs.get("location", gOptions.location)
            checkin_venue=venue(objid=location)
            if kwargs.get("foursquare", False):
                self.data["foursquare"]="on"
                try:
                    checkin_venue=venue(objid=int(location))
                    checkin_venue.update(self)
                    self.data["foursquare_id"]=checkin_venue.foursquareid
                    mylog.info("checkin: Adding venue {0} with 4SQ id {1}".format(location, checkin_venu.foursquareid))
                except ValueError:
                    self.data["foursquare_id"]=location
                    mylog.info("checkin: Trying to check in with non-int location ID, assuming FourSquare MD5 hash: {0}".format(self.data["foursquare_id"]))
            elif gOptions!=None and gOptions.foursquare:
                self.data["foursquare"]="on"
                try:
                    checkin_venue=venue(objid=int(gOptions.location))
                    checkin_venue.update(self)
                    self.data["foursquare_id"]=checkin_venue.foursquareid
                except ValueError:
                    self.data["foursquare_id"]=gOptions.location
                    mylog.info("checkin: Trying to check in with non-int location ID, assuming FourSquare MD5 hash: {0}".format(self.data["foursquare_id"]))
        mylog.warning("checkin: Actual checkin is disabled!!!")
        #myjson=self.__callApi(verb=verb, method=path, params=self.params)["response"]
        #return checkin(json=myjson)
        return True


    def getBeer(self, val):
        mylog.debug("getbeer: trying to get beer: {0}".format(val))
        myjson=self.getBeerJson(val)
        return beer(json=myjson)

    def getBeerJson(self, val):
        mylog.debug("getbeer: trying to get beer: {0}".format(val))
        try:
            val=int(val)
        except ValueError:
            mylog.error("getbeer: Can't look up a beer by non-int values! Was passed: {0}".format(val))
            return None
        path="{0}/{1}".format(self.paths["beer"]["info"]["path"], val)
        myjson=self.__callApi(method=path, verb=self.paths["beer"]["info"]["method"])
        return myjson["response"]["beer"]

    def searchbeer(self, val):
        mylog.debug("searchbeer: trying to search for beer: {0}".format(val))
        beerlist=[]
        offset=0
        found=100
        limit=50
        while offset+limit<found:
            mylog.debug("searchbeer: Asked for up to {0} beers, got {1}, starting at: {2}.".format(limit, found, offset))
            myjson=self.__search("beer", val, offset, limit)
            found=myjson["found"]
            for i in myjson["beers"]["items"]:
                mylog.info("searchbeer: Found {0}".format(i["beer"]["beer_name"]))
                x=beer(json=i["beer"])
                x.brewery=brewery(json=i["brewery"])
                beerlist.append(x)
            offset=offset+limit
        mylog.info("searchbeer.Returning {0} beers.".format(len(beerlist)))
        return beerlist

    def getBrewery(self, val):
        mylog.debug("getbrewery: trying to get brewery: {0}".format(val))
        myjson=self.getBreweryJson(val)
        return brewery(json=myjson)

    def getBreweryJson(self, val):
        mylog.debug("getbrewery: trying to get brewery: {0}".format(val))
        try:
            val=int(val)
        except ValueError:
            mylog.error("ERROR: getbrewery: Can't look up a brewery by non-int values! Was passed: {0}".format(val))
            return None
        path="{0}/{1}".format(self.paths["brewery"]["info"]["path"], val)
        myjson=self.__callApi(method=path, verb=self.paths["brewery"]["info"]["method"])
        return myjson["response"]["brewery"]

    def searchbrewery(self, val):
        mylog.debug("searchbrewery: trying to search for brewery: {0}".format(val))
        brewlist=[]
        offset=0
        found=100
        limit=50
        while offset+limit<found:
            mylog.debug("searchbrewery: Asked for up to {0} brewerys, got {1}, starting at: {2}.".format(limit, found, offset))
            myjson=self.__search("brewery", val, offset, limit)
            found=myjson["found"]
            for i in myjson["brewery"]["items"]:
                mylog.info("searchbrewery: Found {0}".format(i["brewery"]["brewery_name"]))
                brewlist.append(brewery(json=i["brewery"]))
            offset=offset+limit
        mylog.info("searchbrewery: Returning {0} breweries.".format(len(brewlist)))
        return brewlist

    def getUser(self, val, **kwargs):
        mylog.debug("getuser: trying to get user: {0}".format(val))
        myjson=self.getUserJson(val)
        return user(json=myjson)

    def getUserJson(self, val="", **kwargs):
        mylog.debug("getuser: trying to get user: {0}".format(val))
        try:
            val=str(val)
        except ValueError:
            mylog.error("getuser: Can't look up a user by non-{1} values! Was passed: {2}".format(self.paths["user"]["info"]["send"], val))
            return None
        path="{0}/{1}".format(self.paths["user"]["info"]["path"], val)
        myjson=self.__callApi(method=path, verb=self.paths["user"]["info"]["method"], **kwargs)
        return myjson["response"]["user"]

    def getUserBeers(self, val, **kwargs):
        mylog.debug("getuserBeers: trying to get list of beers for user: {0}".format(val))
        try:
            if val==None:
                val=""
            else:
                val=str(val)
        except ValueError:
            #this call works with an empty "val", in which case it assumes self.
            val=""
        path="{0}/{1}".format(self.paths["user"]["beers"]["path"], val)
        myjson=self.__callApi(method=path, verb=self.paths["user"]["beers"]["method"], **kwargs)
        mylog.debug("getUserBeers: Trying to get beer list for user {0}".format(val))
        beerlist=[]
        for i in myjson["response"]["beers"]["items"]:
            beerlist.append(beer(json=i["beer"]))
            #not adding complexity, since this api returns only 25 beers
        return beerlist

    def getCheckins(self, val, **kwargs):
        path=""
        verb=""
        if val:
            # we were asked for a user's checkins
            path="{0}/{1}".format(self.paths["user"]["checkins"]["path"], val)
            verb=self.paths["user"]["checkins"]["method"]
            mylog.debug("getCheckins: Looking for checkinsfor user {0}".format(val))
        else:
            path=self.paths["checkin"]["recent"]["path"]
            verb=self.paths["checkin"]["recent"]["method"]
            mylog.debug("getCheckins: Looking for checkins for self.")
        myjson=self.__callApi(method=path, verb=verb, **kwargs)
        mylog.debug("getCheckins: making call for checkins now...")
        checkinlist=[]
        for i in myjson["response"]["checkins"]["items"]:
            checkinlist.append(checkin(json=i))
        return checkinlist

    def saveresponses(self):
        mylog.debug("saveResponse: Trying to save self.r status codes.")
        result=False
        if self.r is not None:
            self.responses["code"]=self.r.status_code
            mylog.debug("saveResponse: Code: {0}".format(self.responses["code"]))
            mylog.debug("saveResponse: JSON: {0}".format(self.r.text))
            if self.r.status_code == 200:
                mylog.info("saveResponse: No Error, exiting saveResponses.")
                result=True
            else:
                try:
                    self.responses["error"]=self.r.json()["meta"]["error_detail"]
                    self.responses["error_type"]=self.r.json()["meta"]["error_type"]
                    self.responses["friendly"]=self.r.json()["meta"]["developer_friendly"]
                except JSONDecodeError:
                    mylog.info("saveResponse: No JSON returned, only: {0}".format(self.r.text))
        #if self.responses["friendly"] is "" and self.r.text:
        #    self.responses["friendly"] = self.r.text
        mylog.debug("saveResponse: Error: {0}".format(self.responses["error"]))
        mylog.debug("saveResponse: Type: {0}".format(self.responses["error_type"]))
        mylog.debug("saveResponse: Friendly: {0}".format(self.responses["friendly"]))
        return result

class pytappdObject(object):
    def __init__(self, objid=0, name="", json={}):
        '''all pytappd Objects can be initialized empty, or from a dict from r.json()["response"][thing]
        Some can be built from an id or name, and then "object.update(dotappdobject)" can be called,
        which will rebuild the existing object from API call.

          objid=int(object_id)
          name=str(object_name)
          json=dict(json of object)

          updating an object is is sometimes needed even if the object
          was created from json because not all Untappd API methods return a fully
          populated object. FOr example, a dotappd.searchbeer(str(beername)) call returns
          a list of beer objects. But those beer objects do not include fully populated brewery objects.

          This program will not automatically fully populate those brewery objects, because a single search
          Could utilize all 100 API calls your user can make in an hour if we did that full population.
        """
        '''
        if gPythonv==2:
            super(pytappdObject, self).__init__()
        else:
            super().__init__()
        self.apiName="user"
        self.name = name
        self.id=objid
        self.icon="📜"
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
            mylog.info("json.setter: {0}: JSON not initialized from HTTP and none passed in, unsetting self.".format(self.name))
            self.id=0
            self.name=""
            self.__json=None
        else:
            #validate, then set
            if json.get("response", False):
                mylog.info("json.setter: we got back the FULL json from an API call, so we have to de-nest the {0} object.".format(self.apiName))
                searchdict=json["response"][self.apiName]
            else:
                searchdict=json
            #mylog.debug("Now looking through object {0}".format(searchdict))
            for field in self.fields:
                mylog.debug("json.setter: Looking up field {0} in json object.".format(field))
                if searchdict.get(field, None) is None:
                    # got a stub from somewhere else, so set as blank
                    mylog.debug("json.setter: {0}: JSON not complete for this object type, missing field {1}".format(self.name, field))
                    searchdict[field]=None
                if field==self.idfield:
                    # some things return an id and a _type_id, so don't overwrite if we already have an id
                    self.id=searchdict[field]
                    mylog.info("json.setter: found an ID field {0}, setting as ID: {1}".format(field, searchdict[field]))
                elif field==self.namefield:
                    self.name=searchdict[field]
                    mylog.info("json.setter: found a name field {0}, setting as: {1}".format(field, searchdict[field]))
                else:
                    # the name and ID fields have different names for each subclass,
                    # the point of this if/elif is to find those 2 fields in each json returned.
                    #  the line below was debugging when I was writing this section, but it's a bit
                    # too verbose for current code, so I'm replacing it with a 'pass'
                    #mylog.debug("Field {0} is not name or id.".format(field))
                    pass
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
        mylog.debug("id.setter: Setting id for {0} to {1}".format(self.apiName, x))
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
        mylog.debug("name.setter: Setting name for {0} to {1}".format(self.apiName, x))
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
                #mylog.debug("vals: Trying to find {0} in self.json.".format(field))
                try:
                    if getattr(self, field, False):
                        if type(getattr(self,field)) != list:
                            if re.search("icon", field):
                                melist.append(self.icon)
                            melist.append(str(getattr(self,field)))
                        else:
                            melist.append(getattr(self, field)[0].icon)
                    elif type(self.json[field]) != dict:
                        melist.append(str(self.json[field]))
                        #mylog.debug("vals: Found {0}".format(self.json[field]))
                    else:
                        melist.append("{}")
                except IndexError:
                    melist.append("[]")
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
        return self.name
        #global logsep
        #mestring=""
        #if self.json:
        #    mestring=logsep.join(map(str, self.vals))
        #return mestring

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

# 28 lines:
class dummy(pytappdObject):
    '''Help!'''
    def __init__(self, objid=0, name="", json={}):
        '''help!'''
        if gPythonv==2:
            super(beer,self).__init__()
        else:
            super().__init__()
        self.apiName="dummy"
        self.namefield="dummy_name"
        self.idfield="dummy_id"
        self.icon="😒"
        self.headers=[
                "DI",
                "Name",
                ]
        self.fields=[
                'dummy_id',
                'dummy_name',
                ]
        if json=={}:
            mylog.debug("dummy: Init {0} object empty.".format(self.apiName))
            self.__name=name
            self.__id=objid
        else:
            mylog.debug("dummy: Init {0} object from json.".format(self.apiName))
            self.json=json
            if self.json.get("brewery", False):
                # User activity feed has brewery not underneath the beer itself.
                self.brewery=brewery(json=self.json["brewery"])

class badge(pytappdObject):
    """Badges for beers.  Checkins earn badges. This is the class for each one.
    """

    def __init__(self, objid=0, name="", json={}):
        '''Initialize a new badge object empty or with data.
        Data can be empty or should be at least one of:
          objid=int(badge_id)
          name=str(badge_name)
          json=dict(json of badge object)
        '''
        if gPythonv==2:
            super(beer,self).__init__()
        else:
            super().__init__()
        self.apiName="badges"
        self.namefield="badge_name"
        self.idfield="badge_id"
        self.icon="📛"
        self.levels=[]
        self.isactive=False
        self.level=1
        self.headers=[
                "ID",
                "Name",
                "Description",
                "Active?",
                "Media",
                "Created At",
                ]
        self.fields=[
                'badge_id',
                'badge_name',
                'badge_description',
                'badge_active_status',
                'media',
                'created_at',
                ]
        if json=={}:
            mylog.debug("badge: Init {0} object empty.".format(self.apiName))
            self.__name=name
            self.__id=objid
        else:
            mylog.debug("badge: Init {0} object from json.".format(self.apiName))
            self.json=json
            if self.json.get("levels", False):
                mylog.info("badge: Badge {0} has multiple levels earned...".format(self.name))
                for b in json["levels"]["items"]:
                    mylog.info("badge: Adding level {0}".format(self.level))
                    self.levels.append(badge(json=b))
                    self.level+=1

class beer(pytappdObject):
    """Beer!

    Each beer in Untappd has a name, an ID, and a brewery it came from.
    It may have a list of checkins nearby, a list of locations nearby, and other
    variable information, but the name and ID we can trust.

    Only 1 function: self.update, which requires an instatiated dotappd
      object that it can use to authenticate to untappd to update itself
    """
    def __init__(self, objid=0, name="", json={}):
        """
        Data to initialize can be empty should be at least one of:
          objid=int(bid)
          name=str(beer_name)
          json=dict(json of beer object)

          if at least objid or name is provided, "self.update(dotappdobject)"
          will fully populate the object.  THis is sometimes needed even if the object
          was created from json because not all Untappd API methods return a fully
          populated beer object (with media and brewery info).

          """
        if gPythonv==2:
            super(beer, self).__init__()
        else:
            super().__init__()
        self.apiName="beer"
        self.namefield="beer_name"
        self.idfield="bid"
        self.brewery=brewery()
        self.media=[]
        self.icon="🍺"
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
        if json=={}:
            mylog.debug("beer: Init {0} object empty.".format(self.apiName))
            self.__name=name
            self.__id=objid
        else:
            mylog.debug("beer: Init {0} object from json.".format(self.apiName))
            self.json=json
            if self.json.get("brewery", False):
                mylog.info("beer: {0} has a brewery json.".format(self.name))
                # User activity feed has brewery not underneath the beer itself.
                self.brewery=brewery(json=self.json["brewery"])
            elif self.json.get("brewery_name"):
                mylog.info("beer: {0} has a brewery {1}, but no structure.".format(self.name, self.json["brewery_name"]))
                self.brewery=brewery(name=self.json["brewery_name"])
                self.brewery.id=self.json["brewery_id"]
            if self.json.get("media", False):
                mylog.info("beer: {0} has media.".format(self.name))
                for m in self.json["media"]["items"]:
                    mylog.debug("beer: Adding {0} to beer {1}".format(m["photo_id"], self.name))
                    self.media.append(media(json=m))

    def update(self, apiobject):
        mylog.info("beerupdate: Trying to update online for ID: {0}".format(self.id))
        if self.id==0 and self.name=="":
            mylog.warning("beerupdate: Can't look up id 0 online, returning fail!")
            return False
        if self.id!=0:
            self=apiobject.getBeer(self.id)
            return True
        if self.name!="":
            x=apiobject.searchbeer(self.name)
            for b in x:
                if b.name==self.name:
                    self=b
                    return True
        return False

class brewery(pytappdObject):
    '''
    The brewery object, which either gets built inside a beer object, a 
    beer object inside a user, or inside a checkin object. Contains lots of
    beers, hopefully.

    Only 1 function: self.update, which requires an instatiated dotappd
      object that it can use to authenticate to untappd to update itself
    '''
    def __init__(self, objid=0, name="", json={}):
        """Data to initialize can be empty, or at least one of:
          objid=int(brewery_id)
          name=str(brewery_name)
          json=dict(json of brewery object)

          if at least objid or name is provided, "self.update(dotappdobject)"
          will fully populate the object.  THis is sometimes needed even if the object
          was created from json because not all Untappd API methods return a fully
          populated brewery object (with media and beer list).

        """
        if gPythonv==2:
            super(brewery, self).__init__()
        else:
            super().__init__()
        self.apiName="brewery"
        self.namefield="brewery_name"
        self.idfield="brewery_id"
        self.beer_list=[]
        self.icon="🏭"
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
        if json=={}:
            mylog.debug("brewery: Init {0} object empty.".format(self.apiName))
            self.__name=name
            self.__id=objid
        else:
            mylog.debug("brewery: Init {0} object from json.".format(self.apiName))
            self.json=json
            if json.get("beer_list", False):
                mylog.info("brewery: Brewery {0} returned a beer list, filling it out.".format(self.name))
                for b in json["beer_list"]["items"]:
                    self.beer_list.append(beer(json=b["beer"]))

    def update(self, apiobject):
        mylog.info("update: Trying to update online {0}".format(self.name))
        if self.id==0 and self.name=="":
            mylog.warning("update: Can't look up id 0 online, returning fail!")
            return False
        if self.id!=0:
            self=apiobject.getBrewery(self.id)
            return True
        if self.name!="":
            x=apiobject.searchbrewery(self.name)
            for b in x:
                if b.name==self.name:
                    self=b
                    return True
        return False

class checkin(pytappdObject):
    '''Check in a beer!
    Requires a beer, a user, a timezone, and a gmt offset
    as of version 0.10, the timezone and GMT offset are hardset.
    '''
    def __init__(self, objid=0, name="", json={}):
        '''The check-in object is returned by dotappd.checkin() function
        It is not normally initialized empty.
        '''
        if gPythonv==2:
            super(pytappdObject,self).__init__()
        else:
            super().__init__()
        self.apiName="checkin"
        self.namefield="checkin_comment"
        self.idfield="checkin_id"
        self.icon="✔️"
        self.headers=[
                "Checkin ID"
                "Created At",
                "Stats",
                "Rating",
                "User",
                "Beer",
                "Brewery",
                "Venue",
                "Comment",
                "Recommentations",
                "Media_allowed",
                "Source",
                "Follow Status",
                "Promotions",
                "Badges",
                "Result",
                "Badge_Valid",
                ]
        self.fields=[
                'checkin_id',
                'created_at',
                'stats',
                'rating_score',
                'user',
                'beer',
                'brewery',
                'venue',
                'checkin_comment',
                'recommendations',
                'media_allowed',
                'source',
                'follow_status',
                'promotions',
                'badges',
                'result',
                'badge_valid',
                ]
        self.beer=beer()
        self.user=user()
        self.brewery=brewery()
        self.venue=venue()
        self.media=media()
        self.badges=[]
        if json=={}:
            mylog.debug("checkin: Init {0} object empty.".format(self.apiName))
            self.__id=objid
            self.__name=name
            self.brewery=brewery()
            self.beer=beer()
        else:
            mylog.debug("checkin: Init {0} object from json.".format(self.apiName))
            self.json=json
            if self.json.get("brewery", False):
                # Checkin SHOULD have the brewery directly underneath the checkin
                mylog.debug("checkin: Found brewery in checkin.")
                self.brewery=brewery(json=self.json["brewery"])
            if self.json.get("beer", False):
                # Checkin SHOULD have the beer directly underneath the checkin
                mylog.debug("checkin: Found brewery in checkin.")
                self.beer=beer(json=self.json["beer"])
                if not self.brewery:
                    self.beer.brewery=self.brewery(json=self.json["brewery"])
                else:
                    self.beer.brewery=self.brewery
            if self.json.get("media", False):
                # Checkin will have media, unless the user didn't add a picture
                mylog.info("checkin: Found media in checkin.")
                self.media=media(json=self.json["media"])
            if self.json.get("badges", False):
                mylog.info("checkin: Found badges in checkin.")
                for b in self.json["badges"]["items"]:
                    x=badge(json=b)
                    mylog.debug("checkin: Found badge {0}".format(x.name))
                    self.badges.append(x)
            if self.json.get("user", False):
                mylog.info("checkin: Found user in checkin.")
                self.user=user(json=self.json["user"])
            if self.json.get("username", False):
                mylog.info("checkin: Found username in checkin.")
                self.user=user(json=self.json["username"])
            if self.json.get("venue", False):
                mylog.info("checkin: Found venue in checkin.")
                self.venue=venue(json=self.json["venue"])
            mylog.info("checkin: Finished initialing checkin from json data.")


class media(pytappdObject):
    '''Media object - Should only come back inside checkins or
    venues.'''
    def __init__(self, objid=0, name="", json={}):
        '''Initialize a Media object
        Data to initialize can be empty, or at least one of:
          objid=int(media_id)
          name=str(media_name)
          json=dict(json of media object)

        '''
        if gPythonv==2:
            super(media,self).__init__()
        else:
            super().__init__()
        self.apiName="media"
        self.namefield="media_id"
        self.idfield="media_id"
        self.beer=beer()
        self.brewery=brewery()
        self.venue=venue()
        self.user=user()
        self.checkin=0
        self.icon="📷"
        self.headers=[
                "ID",
                "Photo",
                "Created",
                "Checkin ID",
                "Beer",
                "Brewery",
                "User",
                "Venue",
                ]
        self.fields=[
                'photo_id',
                'photo',
                'created_at',
                'checkin_id',
                'beer',
                'brewery',
                'user',
                'venue',
                ]
        if json=={}:
            mylog.debug("media: Init {0} object empty.".format(self.apiName))
            self.__name=name
            self.__id=objid
        else:
            mylog.debug("media: Init {0} object from json.".format(self.apiName))
            self.json=json
            if self.json.get("beer", False):
                mylog.debug("media: This media has an associated beer.")
                self.beer=beer(json=self.json["beer"])
            if self.json.get("brewery", False):
                mylog.debug("media: This media has an associated brewery.")
                self.brewery=brewery(json=self.json["brewery"])
            if self.json.get("venue", False):
                if self.json["venue"] == [[]] or self.json["venue"]==[]:
                    mylog.info("media: the venue for this media is empty.")
                    self.venue=venue()
                else:
                    mylog.debug("media: This media has an associated venue.")
                    self.venue=venue(json=self.json["venue"][0])
            if self.json.get("user", False):
                mylog.debug("media: This media has an associated user.")
                self.user=user(json=self.json["user"])
            if self.json.get("checkin_id"):
                mylog.debug("media: This media has an associated checkin.")
                self.checkin=self.json["checkin_id"]

class user(pytappdObject):
    '''The user object (TBD)
    '''
    def __init__(self, objid=0, name="", json={}):
        """Data to initialize can be empty, or at least one of:
          objid=int(uid)
          name=str(username)
          json=dict(json of user object)

          if at least objid or name is provided, "self.update(dotappdobject)"
          will fully populate the object.  THis is sometimes needed even if the object
          was created from json because not all Untappd API methods return a fully
          populated user object.
        """
        if gPythonv==2:
            super(user, self).__init__()
        else:
            super().__init__()
        self.apiName="user"
        self.namefield="user_name"
        self.idfield="uid"
        self.recent_brews=[]
        self.icon="🥴"
        self.headers=[
                "ID",
                "Name",
                "First Name",
                "Last Name",
                "Avatar",
                "Cover Photo",
                "Private?",
                "Location",
                "URL",
                "Bio",
                "Supporter?",
                "Relationship",
                "Untappd Link",
                "Stats",
                "Recent",
                ]
        self.fields=[
                'uid',
                'user_name',
                'first_name',
                'last_name',
                'user_avatar',
                'user_cover_photo',
                'is_private',
                'location',
                'url',
                'bio',
                'is_supporter',
                'relationship',
                'untappd_url',
                'stats',
                'recent_brews',
                ]
        if json=={}:
            mylog.debug("user: Init {0} object empty.".format(self.apiName))
            self.__name=name
            self.__id=objid
        else:
            mylog.debug("user: Init {0} object from json.".format(self.apiName))
            self.json=json
            if json.get("recent_brews", False):
                for item in json["recent_brews"]["items"]:
                    if item.get("beer", False):
                        mylog.debug("user: Found beer: {0}, which is raw: {1}.".format(item["beer"]["beer_name"], item))
                        x=beer(json=item["beer"])
                        x.brewery=brewery(json=item.get("brewery", {}))
                        self.recent_brews.append(x)
                        mylog.info("user: Found beer: {0}".format(x.name))

class venue(pytappdObject):
    '''Venue object - requires FourSquare City Lookup'''
    def __init__(self, objid=0, name="", json={}):
        """Data to initialize can be empty, or at least one of:
          objid=int(venue_id)
          name=str(venue_name)
          json=dict(json of venue object)

          if at least objid or name is provided, "self.update(dotappdobject)"
          will fully populate the object.  THis is sometimes needed even if the object
          was created from json because not all Untappd API methods return a fully
          populated venue object (with beer list and media).
        """
        if gPythonv==2:
            super(beer,self).__init__()
        else:
            super().__init__()
        self.apiName="venue"
        self.namefield="venue_name"
        self.idfield="venue_id"
        self.foursquareid=""
        self.icon="🌃"
        self.headers=[
                "ID",
                "Name",
                "Last Updated",
                "Category",
                "Categories++",
                "Stats",
                "Icon",
                "Public",
                "Location",
                "Contact",
                "FourSquare",
                "Media",
                ]
        self.fields=[
                'venue_id',
                'venue_name',
                'last_updated',
                'primary_category',
                'categories',
                'stats',
                'venue_icon',
                'public_venue',
                'location',
                'contact',
                'foursquare',
                'media',
                ]
        self.media=[]
        if json=={}:
            mylog.debug("venue: Init {0} object empty.".format(self.apiName))
            self.__name=name
            self.__id=objid
        else:
            mylog.info("venue: Init {0} object from json.".format(self.apiName))
            mylog.debug("venue: Got full json: {0}".format(json))
            self.json=json
            if json.get("media", False):
                for item in json["media"]["items"]:
                    self.media.append(media(json=item))
                    mylog.info("venue: Found media ID: {0}".format(item["photo_id"]))
            if json.get("foursquare", False):
                self.foursquareid=json["foursquare"]["foursquare_id"]
                mylog.info("Found 4square ID {0}, saving.".format(self.foursquareid))

    def update(self, apiobject):
        mylog.info("Trying to update online for ID: {0}".format(self.id))
        if self.id==0:
            mylog.warning("Can't look up id 0 online, returning fail!")
            return False
        self.json=apiobject.getVenueJson(self.id)

def do(objtype, **kwargs):
    mylog.debug("dispatching action: {0}".format(kwargs["act"]))
    mylog.debug("passing arguments: {0}".format(kwargs))
    action=kwargs["act"]
    mylog.debug("running self.actions[{0}], which is: {1}".format(action, objtype.actions[action]))
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
    parser.add_argument('-r', "--rating",
            type=int,
            help="Rating for beer checkin.",
            default=0,
            )
    parser.add_argument('-s', "--shout",
            type=str,
            help="Comment for checkin or toast",
            default="",
            )
    parser.add_argument('-i', '--twitter',
            action='store_true',
            help="Send the checkin to Twitter",
            )
    parser.add_argument('-4', '--foursquare',
            action='store_true',
            help="Send the checkin to FourSquare/Swarm",
            )
    parser.add_argument('-z', '--facebook',
            action='store_true',
            help="Send the checkin to Facebook",
            )
    parser.add_argument('--sort',
            type=str,
            help="sorting order",
            )
    parser.add_argument('--offset',
            type=int,
            help="Offset for search functions",
            )
    parser.add_argument('--limit',
            type=int,
            help="Limit of results to return, if supported.",
            )
    gOptions=parser.parse_args(argv)

    if gOptions.loglevel<=1:
        mylog.setLevel(logging.CRITICAL)
        reqlog.setLevel(logging.CRITICAL)
        logging.getLogger("urllib3").setLevel(logging.CRITICAL)
    elif gOptions.loglevel<=2:
        mylog.setLevel(logging.ERROR)
        reqlog.setLevel(logging.ERROR)
        logging.getLogger("urllib3").setLevel(logging.ERROR)
    elif gOptions.loglevel<=3:
        mylog.setLevel(logging.WARNING)
        reqlog.setLevel(logging.WARNING)
        logging.getLogger("urllib3").setLevel(logging.WARNING)
    elif gOptions.loglevel<=4:
        mylog.setLevel(logging.INFO)
        reqlog.setLevel(logging.INFO)
        logging.getLogger("urllib3").setLevel(logging.INFO)
    elif gOptions.loglevel<=5:
        mylog.setLevel(logging.DEBUG)
        reqlog.setLevel(logging.DEBUG)
        logging.getLogger("urllib3").setLevel(logging.DEBUG)


    untappd=dotappd("")
    untappd.authObject=authObject(gOptions.config)
    mything=None
    myfunc=None
    myactions=dict()
    for thing in untappd.paths.keys():
        for func in untappd.paths[thing].keys():
            mylog.debug("Inspecting {0}, {1} as possible action pairs.".format(thing, func))
            myactions.setdefault(func, list()).append(thing)

    if len(myactions[gOptions.action]) <2:
        mything=myactions[gOptions.action][0]
        mylog.debug("Only one thing, {0} can do the action {1} requested.".format(mything, gOptions.action))
        myfunc=untappd.paths[mything][gOptions.action]["func"]
    elif gOptions.thing in untappd.paths:
        mything=untappd.paths[gOptions.thing]
        myfunc=untappd.paths[gOptions.thing][gOptions.action]["func"]
    else:
        mylog.error("invalid thing requested. Use -t help for a full list")
        sys.exit(2)

    if gMultiple:
        if gOptions.file:
            gMultiple=open(gOptions.file)

        headerline=gMultiple.readline().replace('\r', "")
        headerline=headerline.replace('\n', "")
        fields=headerline.split(logsep)
        mylog.debug("{0} fields: {1}".format(len(fields), headerline))
        line=gMultiple.readline()
        printheader=True
        while line!="":
            line = line.replace('\r', "")
            line = line.replace('\n', "")
            mylog.info("reading line: {0}".format(line))
            parts=line.split(logsep)
            try:
                for i in range(len(fields)):
                    if (not hasattr(gOptions, fields[i])) or (not getattr(gOptions, fields[i], False)):
                        mylog.info("field {0} to value {1}.".format(fields[i], parts[i]))
                    else:
                        mylog.info("{0} from file with {1}.".format(fields[i], getattr(gOptions, fields[i])))
            except IndexError:
                mylog.error("mismatch - there are too few fields in the line: ")
                mylog.error(line)
                mylog.error("Expected {0} fields.".format(len(fields)))
                sys.exit(4)
            line=gMultiple.readline()
            printheader=False  #this will disable printing headers in the rest of the objects we print out, so that an easier report can be saved

    else:
        p=myfunc(vars(gOptions).get(gOptions.thing, ""))
        try:
            mylog.debug("Was returned a {0} object".format(type(p)))
            if type(p) == list:
                mylog.debug("Got a list, printing headers first...")
                printline(logsep.join(p[0].headers))
                for i in p:
                    printline(logsep.join(i))
            else:
                mylog.debug("got a single item, printing headers then the one line.")
                printline(logsep.join(p.headers))
                printline(logsep.join(p))
        except brokenpipeerror:
            sys.exit(32)

    mylog.info("we are done.")
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
p=pytappd.dotappd("docsmooth")
p.authObject=pytappd.authObject(config="../auth.ini")

me=p.getUser("")
for b in me.recent_brews:
    print("{0}, {1}".format(b.name, b.brewery.name))

mybeers=p.searchbeer("sierra nevada flipside red")
for i in mybeers:
    print("{0}, {1}".format(i.name, i.brewery.name))
    i.update(p)

mybeer=p.getBeer(1027618)

'''
