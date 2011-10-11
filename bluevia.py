# 
# The MIT license
#
# Copyright (C) 2011 by Bernhard Walter ( @bernhard42 )
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#

#
# Version 01.08.2011
#

import oauth2 as oauth
import httplib2, pickle, os, types, time, urllib, simplejson, uuid
from types import *
from bluevia_helpers import _parseAdResponse
from bluevia_helpers import _encodeMultipart
from bluevia_helpers import _decodeMultipart

# # # # # # # # # # # # # # # # 
# base Class
# # # # # # # # # # # # # # # #

class BlueVia():
    """
    The BlueVia base class. All other BlueVia classes are inherited from this class BlueVia. 
    
    Mainly Stores consumer and access_token, provides the generic _signAndSend(...) a debug() method
 
    HOWTO USE
    =========
    
    oAuth routines 
    --------------
    
        >>> o = bluevia.BlueViaOauth('<secret>', '<key>')
        >>> o.fetch_request_token()
    
    Returns the oAuth URL for user authorization 
    
    Successful authorization returns an oAuth verifier
    
        >>> o.fetch_access_token("<verifier>")
        >>> o.saveAccessToken("newtok.pkl")

    
    SMS outbound routines
    ---------------------
    
        >>> s = bluevia.BlueViaOutboundSms()
        >>> s.loadAccessToken("newtok.pkl")
        >>> s.sendSMS([myMobileNumber], "Hallo Welt")
    
    Returns the delivery URL  
    
        >>> s.deliveryStatus("<deliveryURL>")
    
    SMS receive routines
    --------------------
    
    For Sandbox testing use an app that can both send SMS and receive SMS with keyword "BlueViaRocks"

    1) Send a fake SMS
    
        >>> s = bluevia.BlueViaOutboundSms()
        >>> s.loadAccessToken("smsmo.pkl")
        >>> s.sendSMS(["445480605"], "SANDBlueViaRocks so much!")

    2) Receive SMS with App
    
        >>> i = bluevia.BlueViaInboundSMS()
        >>> i.loadAccessToken("smsmo.pkl")
        >>> i.receiveSMS("445480605") # UK shortcode

    For live testing use a mobile from the developer (e.g. the one owning the application)    

    1) Send  "TESTBlueViaRocks so much live!" to 445480605

    2) Retrieve from Test System
    
        >>> i = bluevia.BlueViaInboundSMS("") # set sandbox parameter to "" makes test calls
        >>> i.loadAccessToken("smsmo.pkl")
        >>> i.receiveSMS("445480605")
    
    Location routines
    -----------------
    
        >>> l = bluevia.BlueViaLocation()
        >>> l.loadAccessToken("newtok.pkl")
        >>> l.locateTerminal():

    User context routines
    ---------------------
    
        >>> u = bluevia.BlueViaUserContext()
        >>> u.loadAccessToken("newtok.pkl")
        >>> u.getInfo():
    
    Advertising routines
    --------------------
    
        >>> a = bluevia.BlueViaAds("<adspace Id>")
        >>> a.loadAccessToken("newtok.pkl")
        >>> a.getAd_3l(keywordList = ["sport"])

    Payment routines
    ----------------

        >>> p = bluevia.BlueViaPayment('<secret>', '<key>')
        >>> p.fetch_request_token(<amount>, <currency>, <serviceId>, <serviceName>)
        >>> p.fetch_access_token(<verifier>)
        >>> p.savePaymentInfo("payment.pkl") # optional, token valid for 48 h
        >>> p.loadPaymentInfo("payment.pkl") # optional
        >>> p.issuePayment()
        >>> p.checkPayment(<transactionId>)
    """

    access_token = None
    consumer     = None
    realm        = None
    environment  = ""
    version      = None
    debugFlag    = False
    
    http = httplib2.Http()
    

    def _signAndSend(self, requestUrl, method, token, parameters={}, body="", \
                     extraHeaders={}, is_form_encoded = False):
        """
        Generic method to call an oAuth authorized API in BlueVia including oAuth signature.
        
        @param requestUrl: (string):       The BlueVia URL
        @param method: (string):           HTTP method, "GET" or "POST"
        @param token: (oauth.Token):       Usually the Access Token. During oAuth Dance None or Request Token

        @param parameters: (dict):         Necessary call paramters, e.g. version, alt. Default: None
        @param body: (string):             Body of the HTTP call. Default: ""
        @param extraHeaders: (dict):       Some calls need extra headers, e.g. {"Content-Type":"application/json"}. Default: None
        @param is_form_encoded: (boolean): If True parameters are send as form encoded HTTP body. DEFAULT: False
        
        @return: (tuple):                  (HTTP response, HTTP response data)
        """
        
        req = oauth.Request.from_consumer_and_token(self.consumer, token, method, requestUrl, \
                                                    parameters, body, is_form_encoded)
        req.sign_request(oauth.SignatureMethod_HMAC_SHA1(), self.consumer, token)

        headers = req.to_header(realm=self.realm)
        if parameters.has_key("xoauth_apiName"):
            headers['Authorization'] += ', xoauth_apiName="%s"' % parameters.get("xoauth_apiName")
            
        if extraHeaders:
            headers.update(extraHeaders)

        if is_form_encoded:
            # get version and alt parameter only
            params = [p for p in parameters.items() if p[0] in ["version","alt"]]
        else:
            # remove oauth_ parameters like oauth_callback
            params = [p for p in parameters.items() if p and p[0][:6] != "oauth_"]

        query = None
        if params:
            query = "&".join(["%s=%s" % (p[0], p[1]) for p in params])
            if query:
                requestUrl += "?" + query

        if self.debugFlag: self._debug(requestUrl, query, headers, body, token, req)

        response, content = self.http.request(requestUrl, method, body, headers)
        
        if self.debugFlag:
            print('response["status"] = %s' % response["status"])
            print('content =\n %s' % content)
            
        return response, content


    def loadAccessToken(self, path):
        """
        Load Consumer Credentials and Access Token from disk (pickle file).
        
        @note: 
        Unencrypted storage. Use only for testing!
        
        @param path: (string): Path to pickle file
        
        @return: (boolean):    True if successfully loaded
        """

        if os.path.exists(path):
            fd = open(path, "r")
            self.consumer, self.access_token = pickle.load(fd)
            fd.close()
            return True
        else:
            return False
    

    def setConsumer(self, consumer):
        """
        Set the Consumer credentials.
        
        @param consumer: (oauth.Token): The consumer credentials as provided by getCosumer in class BlueViaOauth
        """
        
        self.consumer = consumer
    
        
    def setAccessToken(self, access_token):
        """
        Set the Access Token.
        
        @param access_token: (oauth.Token): The oAuth access token as provided by getAccessToken in class BlueViaOauth
        """
        
        self.access_token = access_token
    
        
    def hasCredentials(self):
        """
        Check availability of access token 
        """

        return (self.consumer != None) and (self.access_token != None)
    

    def setDebug(self, dbgFlag):
        """
        Set or unset the debug flag
        
        @param dbgFlag: (boolean): If True debug information will be printed to stdout
        """
        
        self.debugFlag = dbgFlag
    

    def _debug(self, requestUrl, query, headers, body, token, req):
        """
        Prints aut anything relevant for oAuth debugging: URL, method, body, headers, signature base string, ...

        @note: Internal method
        """
        
        print("\nurl   = " + requestUrl)
        if not query: query = ""
        print("\nquery = " + query)
        print("\nhead  = " + simplejson.dumps(headers, indent = 2).replace(", ", ",\n"))
        try:
            bstr = simplejson.dumps(simplejson.loads(body), indent = 2)
        except:
            bstr = body
        print("\nbody  = " + bstr)
        sm =  oauth.SignatureMethod_HMAC_SHA1()
        key, base = sm.signing_base(req, self.consumer, token)
        print("\noAuth signature components")
        print("\nbase  = " + base)
        print("\nkey   = " + key)
    

# # # # # # # # # # # # # # # # 
# oAuth Class
# # # # # # # # # # # # # # # # 
        
class BlueViaOauth(BlueVia):
    """
    This class provides the methods for the oAuth Dance.
    It supports Out Of Band authorization as defined in oAuth 1.0a 
    """
    
    def __init__(self, consumer_key, consumer_secret, realm="BlueVia"):
        """
        Initialize the BlueViaOauth object
        
        @param consumer_key: (string):     Key of the Consumer Credentials
        @param consumer_secret: (string):  Secret of the Consumer Credentials
        
        @param realm: (string):            Realm string. Default: "BlueVia"
        """
        
        self.realm = realm
        self.consumer = oauth.Consumer(consumer_key, consumer_secret)
        self.request_token_url = 'https://api.bluevia.com/services/REST/Oauth/getRequestToken'
        self.access_token_url  = 'https://api.bluevia.com/services/REST/Oauth/getAccessToken'
        self.authorization_url = 'https://connect.bluevia.com/authorise'
        self.request_token = None
    
        
    def fetch_request_token(self, callback="oob"):
        """
        First call of the oAuth Dance. Provide the Consumer Credential and request the Request Token
        
        @param callback: (string): The callback URL or "oob". Default: "oob"
        
        @return: (tuple):           (HTTP status, authorization URL). HTTP status == "200" for success
        """
        
        
        response, content = self._signAndSend(self.request_token_url, "POST", None, parameters={"oauth_callback":callback})
        if response["status"] == '200':
            self.request_token = oauth.Token.from_string(content)
            return int(response["status"]), "%s?oauth_token=%s" % (self.authorization_url, self.request_token.key)
        else:
            return int(response["status"]), content
    
   
    def fetch_access_token(self, verifier):
        """
        The final step of the oAuth Dance. Exchange the Request Token with the Access Token
        
        @param verifier: (string): The oAuth verifier of the successful user authorization
        
        @return: (string):         HTTP status == "200" for success
        """
        
        assert type(verifier) is StringType and verifier!= "", "Oauth 'verifier' must be a non empty string"
        
        self.request_token.set_verifier(verifier)
        response, content = self._signAndSend(self.access_token_url, "POST", self.request_token, parameters={})
        if response["status"] == '200':
            self.access_token = oauth.Token.from_string(content)
            return int(response["status"])
        else:
            return int(response["status"]), content
    

    def saveAccessToken(self, path):
        """
        Save the Access Token.
        
        Note: Unencrypted storage. Use only during development
        
        @param path: (string): Path to file on disk (pickle file)
        """

        assert type(path) is StringType and path!= "", "'path' must be a non empty string"

        fd = open(path, "w")
        pickle.dump((self.consumer, self.access_token), fd)
        fd.close()
    

    def getConsumer(self):
        """
        Retrieve the Consumer Credentials
        """
        
        return self.consumer
    
        
    def getAccessToken(self):
        """
        Retrieve the Access Token
        """
        
        return self.access_token    
    

# # # # # # # # # # # # # # # # 
# Outbound SMS Class
# # # # # # # # # # # # # # # # 

class BlueViaOutboundSms(BlueVia):
    """
    The BlueVia class for sending and tracking SMS.
    """
        
    def __init__(self, sandbox = "_Sandbox", realm = "BlueVia", version="v1"):
        """
        Initialize the BlueViaOutboundSms object
         
        @param sandbox: (string): Indicates whether testing should be done in Sandbox mode. Use "" for real network access; Default: "_Sandbox"
        @param realm: (string): Realm string; Default: "BlueVia"
        @param version: (string): BlueVia API version; Default: "v1"
        """
        
        self.environment = sandbox
        self.realm = realm
        self.version = version
        self.outbound_sms_url  = "https://api.bluevia.com/services/REST/SMS%s/outbound/requests"
    

    def sendSMS(self, addresses, message):
        """
        Send SMS via BlueVia to one or more recipients
        
        @param addresses: (array): An array of mobile numbers (string) in the form "44 (for UK) 7764735478" (Mobile number without first zero and no spaces)
        @param message: (string):  A maximum 160 char string containing the SMS message
        
        @return: (tuple):           (HTTP status, deliveryURL). HTTP status == "201" for success. Use deliverURL in method deliverStatus.
        """
        
        assert self.hasCredentials(), "load oAuth credentials first or execute oAuth Dance"
        assert (type(addresses) is ListType and addresses!=[]) or \
               (type(addresses) is StringType and addresses!="") , "'addresses' must be a non empty string or a non empty array of strings"
        assert type(message) is StringType and message!= "", "'message' must be a non empty string"

        if type(addresses) == types.StringType:
            addresses = [addresses]
        addrlist = ",".join(['{"phoneNumber":"%s"}' % a for a in addresses])
        if len(addresses) > 1: addrlist = '[%s]' % addrlist
        
        body = '{"smsText": {"address": %s,"message": "%s", "originAddress": {"alias": "%s"}}}' \
               % (addrlist, message, self.access_token.key)

        parameters = {"version":self.version, "alt":"json"}

        response, content = self._signAndSend(self.outbound_sms_url % self.environment, "POST", self.access_token, \
                                              parameters=parameters, body=body, \
                                              extraHeaders={"Content-Type":"application/json;charset=UTF8"})
        if response["status"] == '201':
            return int(response["status"]), response["location"]
        else:
            return int(response["status"]), content
    

    def deliveryStatus(self, deliveryURL):
        """
        Track the delivery of a BlueVia SMS
        
        @param deliveryURL: (string): deliveryURL provided by sendSMS method

        @return: (tuple):              (HTTP status, (dict) deliveryReceipt). HTTP status == "200" for success.          
        """
        
        assert self.hasCredentials(), "load oAuth credentials first or execute oAuth Dance"
        assert type(deliveryURL) is StringType and deliveryURL!= "", "'deliveryURL' must be a non empty string"

        parameters = {"version":self.version, "alt":"json"}
        response, content = self._signAndSend(deliveryURL, "GET", self.access_token, parameters=parameters)
        if response["status"] == '200':
            return int(response["status"]), simplejson.loads(content)["smsDeliveryStatus"]
        else:
            return int(response["status"]), content
    

# # # # # # # # # # # # # # # # 
# Inbound SMS Class
# # # # # # # # # # # # # # # # 

class BlueViaInboundSMS(BlueVia):
    """
    The BlueVia class for receiving SMS.
    """
        
    def __init__(self, sandbox = "_Sandbox", realm = "BlueVia", version="v1"):
        """
        Initialize the BlueViaInboundSMS object
        
        @param sandbox: (string): Indicates whether testing should be done in Sandbox mode. Use "" for real network access; Default: "_Sandbox", 
        @param realm: (string): Realm string; Default: "BlueVia"
        @param version: (string): BlueVia API version; Default: "v1"
        """
        
        self.environment = sandbox
        self.realm = realm
        self.version = version
        self.inbound_sms_url = "https://api.bluevia.com/services/REST/SMS%s/inbound/%s/messages"
        self.inbound_notification_url = "https://api.bluevia.com/services/REST/SMS%s/inbound/subscriptions"

    def receiveSMS(self, shortcode):
        """
        Receive all SMS sent to the shortcode with the Keyword defined during BlueVia App generation
        
        @param shortcode: (string): SMS shortcode including country code without "+", e.g. "44"
        
        @return: (tuple):           (HTTP status, (dict) receivedSMS). HTTP status == "200" for success.                  
        """
        
        assert self.hasCredentials(), "load oAuth credentials first or execute oAuth Dance"
        assert type(shortcode) is StringType and shortcode!= "", "'shortcode' must be a non empty string"
        
        url = self.inbound_sms_url % (self.environment, shortcode)
        parameters = {"version":self.version, "alt":"json"}
        response, content = self._signAndSend(url, "GET", self.access_token, parameters=parameters)
        if response["status"] == '200':
            return int(response["status"]), simplejson.loads(content)['receivedSMS']
        else:
            return int(response["status"]), content
            
            
    def subscribeNotifications(self, shortcode, keyword, endpoint, correlator):
        """
        Subscribe to Receive SMS notifications
        
        @param shortcode: (string): SMS shortcode including country code without "+", e.g. "44"
        @param keyword: (string): The registered SMS Keyword of the application
        @param endpoint: (string): The url to which BlueVia shall post the relevant SMS
        @param correlator: (string): The correlator allows to identify the subscription

        @return: (tuple):           (HTTP status, unsubscribeURL). HTTP status == "201" for success. Use unsubscribeURL in method unsubscribeNotifications.
        """

        assert self.hasCredentials(), "load oAuth credentials first or execute oAuth Dance"
        assert type(shortcode) is StringType and shortcode!= "", "'shortcode' must be a non empty string"
        
        url = self.inbound_notification_url % (self.environment)
 
        body = '{"smsNotification": {\
            "reference": { "correlator": "%s", "endpoint": "%s"}, \
            "destinationAddress": {"phoneNumber": "%s"}, \
            "criteria": "%s" }}}' % (correlator, endpoint, shortcode, keyword)

        parameters = {"version":self.version, "alt":"json"}

        response, content = self._signAndSend(url, "POST", self.access_token, \
                                              parameters=parameters, body=body, \
                                              extraHeaders={"Content-Type":"application/json;charset=UTF8"})
        if response["status"] == '201':
            return int(response["status"]), response["location"]
        else:
            return int(response["status"]), content

    def unsubscribeNotifications(self, url):
        """
        Unsubscribe to Receive SMS notifications
        
        @param url: (string): The unsubscribe URL returned by the subscribeNotifications method 

        @return: (tuple):           (HTTP status, unsubscribeURL). HTTP status == "204" for success.
        """

        parameters = {"version":self.version}
        response, content = self._signAndSend(url, "DELETE", self.access_token, parameters=parameters)
        
        return int(response["status"]), content
        
# # # # # # # # # # # # # # # # 
# Outbound MMS Class
# # # # # # # # # # # # # # # # 

class BlueViaOutboundMms(BlueVia):
    """
    The BlueVia class for sending and tracking MMS.
    """
    
    def __init__(self, sandbox = "_Sandbox", realm = "BlueVia", version="v1"):
        """
        Initialize the BlueViaOutboundMms object
        
        @param sandbox: (string): Indicates whether testing should be done in Sandbox mode. Use "" for real network access; Default: "_Sandbox", 
        @param realm: (string): Realm string; Default: "BlueVia"
        @param version: (string): BlueVia API version; Default: "v1"
        """
        
        self.environment = sandbox
        self.realm = realm
        self.version = version
        self.outbound_mms_url = "https://api.bluevia.com/services/REST/MMS%s/outbound/requests"
    
            
    def sendMMS(self, addresses, subject, messages, attachments):
        """
        Send MMS via BlueVia to one or more recipients
        
        @param addresses: (array):   An array of mobile numbers in the form "44 (for UK) 7764735478" (Mobile number without first zero and no spaces)
        @param subject: (string):    MMS subject text
        @param messages: (array):    An array containing the messages (string)
        @param attachments: (array): An array of paths to files (string) to be sent with MMS
        
        @return: (tuple):             (HTTP status, deliveryURL). HTTP status == "201" for success. Use deliverURL in method deliverStatus.
        """
        
        assert self.hasCredentials(), "load oAuth credentials first or execute oAuth Dance"
        assert (type(addresses) is ListType and addresses!=[]) or \
               (type(addresses) is StringType and addresses!="") , "'addresses' must be a non empty string or a non empty array of strings"
        assert type(subject) is StringType and subject!= "", "'subject' must be a non empty string"
        assert type(messages) is ListType and messages!=[], "'messages' must be a non empty array of strings"
        assert type(attachments) is ListType and attachments!=[], "'attachments' must be a non empty array of strings"

        if type(addresses) == types.StringType:
            addresses = [addresses]
        addrlist = ",".join(['{"phoneNumber":"%s"}' % a for a in addresses])
        if len(addresses) > 1: addrlist = '[%s]' % addrlist

        root = '{"message": {"address": %s,"subject": "%s", "originAddress": {"alias": "%s"}}}' \
               % (addrlist, subject, self.access_token.key)

        body, headers = _encodeMultipart(root, messages, dict([[x,x] for x in attachments]))

        parameters={"version":self.version, "alt":"json"}
        
        response, content = self._signAndSend(self.outbound_mms_url % self.environment, "POST", self.access_token, \
                                              parameters=parameters, body=body, extraHeaders=headers)
        if response["status"] == '201':
            return int(response["status"]), response["location"]
        else:
            return int(response["status"]), content
    

    def deliveryStatus(self, deliveryURL):
        """
        Track the delivery of a BlueVia MMS
        
        @param deliveryURL: (string): deliveryURL provided by sendMMS method

        @return: (tuple):              (HTTP status, (dict) deliveryReceipt). HTTP status == "200" for success.          
        """
        
        assert self.hasCredentials(), "load oAuth credentials first or execute oAuth Dance"
        assert type(deliveryURL) is StringType and deliveryURL!= "", "'deliveryURL' must be a non empty string"

        parameters = {"version":self.version, "alt":"json"}
        response, content = self._signAndSend(deliveryURL, "GET", self.access_token, parameters=parameters)
        if response["status"] == '200':
            return int(response["status"]), simplejson.loads(content)["messageDeliveryStatus"]
        else:
            return int(response["status"]), content
    
        
# # # # # # # # # # # # # # # # 
# Inbound MMS Class
# # # # # # # # # # # # # # # # 

class BlueViaInboundMMS(BlueVia):
    """
    The BlueVia class for receiving MMS and retrieving MMS attachments.
    """
        
    def __init__(self, sandbox = "_Sandbox", realm = "BlueVia", version="v1"):
        """
        Initialize the BlueViaInboundMMS object
        
        @param sandbox: (string): Indicates whether testing should be done in Sandbox mode. Use "" for real network access; Default: "_Sandbox"
        @param realm: (string): Realm string; Default: "BlueVia"
        @param version: (string): BlueVia API version; Default: "v1"
        """
        
        self.environment = sandbox
        self.realm = realm
        self.version = version
        self.inbound_mms_url     = "https://api.bluevia.com/services/REST/MMS%s/inbound/%s/messages"
        self.attachments_mms_url = "https://api.bluevia.com/services/REST/MMS%s/inbound/%s/messages/%s"
    

    def receiveMMS(self, shortcode):
        """
        Receive all MMS sent to the shortcode with the Keyword defined during BlueVia App generation
        
        This method returns the message ids necessary to retrieve the MMS attachments
        
        @param shortcode: (string): MMS shortcode including country code without "+", e.g. "44"
        
        @return: (tuple):           (HTTP status, (dict) receivedSMS). HTTP status == "200" for success.                  
        """
        
        assert self.hasCredentials(), "load oAuth credentials first or execute oAuth Dance"
        assert type(shortcode) is StringType and shortcode!= "", "'shortcode' must be a non empty string"

        url = self.inbound_mms_url % (self.environment, shortcode)
        parameters = {"version":self.version, "alt":"json"}
        response, content = self._signAndSend(url, "GET", self.access_token, parameters=parameters)
        if response["status"] == '200':
            return int(response["status"]), simplejson.loads(content)['receivedMessages']
        else:
            return int(response["status"]), content
    

    def retrieveAttachments(self, shortcode, messageId):
        """
        Retrueve the MMS attachments
        
        @param shortcode: (string): MMS shortcode including country code without "+", e.g. "44"
        @param messageId: (string): The message Id recieved by receiveMMS method
        
        @return: (tuple): (HTTP status, ((int) count, (string) folder)). HTTP status == "200" for success.
                         Writes <count> decoded files into <folder> 
        """

        assert self.hasCredentials(), "load oAuth credentials first or execute oAuth Dance"
        assert type(shortcode) is StringType and shortcode!= "", "'shortcode' must be a non empty string"
        assert type(messageId) is StringType and messageId!= "", "'messageId' must be a non empty string"

        url = self.attachments_mms_url % (self.environment, shortcode, messageId)
        parameters = {"version":self.version, "alt":"json"}
        response, content = self._signAndSend(url, "GET", self.access_token, parameters=parameters)

        if response["status"] == '200':
            return int(response["status"]), _decodeMultipart(messageId, content)
        else:
            return int(response["status"]), content
    


# # # # # # # # # # # # # # # # 
# User Context Class
# # # # # # # # # # # # # # # # 

class BlueViaUserContext(BlueVia):
    """
    The BlueVia class for retrieving information about user and terminal.
    """  

    def __init__(self, sandbox = "_Sandbox", realm = "BlueVia", version="v1"):
        """
        Initialize the BlueViaUserContext object
        
        @param sandbox: (string): Indicates whether testing should be done in Sandbox mode. Use "" for real network access; Default: "_Sandbox"
        @param realm: (string): Realm string; Default: "BlueVia"
        @param version: (string): BlueVia API version; Default: "v1"
        """
        
        self.environment = sandbox
        self.realm = realm
        self.version = version
        self.user_context_url  = "https://api.bluevia.com/services/REST/Directory%s/alias:%s/UserInfo%s"
    

    def _getInfo(self, infoType, resultKey):
        """
        Internal method.
        """
        
        assert self.hasCredentials(), "load oAuth credentials first or execute oAuth Dance"

        url = self.user_context_url % (self.environment, self.access_token.key, infoType)
        parameters = {"version":self.version, "alt":"json"}
        response, content = self._signAndSend(url, "GET", self.access_token, parameters=parameters)
        if response["status"] == '200':
            return int(response["status"]), simplejson.loads(content)[resultKey]
        else:
            return int(response["status"]), content     
    

    def getUserInfo(self):
        """
        Retrieve all available info about the user.
        Aggregates getPersonalInfo, getProfileInfo, getAccessInfo, getTerminalInfo
        
         @return: (tuple): (HTTP status, (dict) userInfo). HTTP status == "200" for success. 
         """

        return self._getInfo("", "userInfo")
    

    def getPersonalInfo(self):
        """
        Retrieve personal info about the user (depending on country, see www.bluevia.com)

        @return: (tuple): (HTTP status, (dict) userPersonalInfo). HTTP status == "200" for success. 
        """
        
        return self._getInfo("/UserPersonalInfo", "userPersonalInfo")
    
 
    def getProfileInfo(self):
        """
        Retrieve info about the user's profile (depending on country, see www.bluevia.com)

        @return: (tuple): (HTTP status, (dict) userProfileInfo). HTTP status == "200" for success. 
        """

        return self._getInfo("/UserProfile", "userProfile")
    

    def getAccessInfo(self):
        """
        Retrieve info about the user's access type (depending on country, see www.bluevia.com)
 
        @return: (tuple): (HTTP status, (dict) userAccessInfo). HTTP status == "200" for success. 
       """

        return self._getInfo("/UserAccessInfo", "userAccessInfo")
    

    def getTerminalInfo(self):
        """
        Retrieve info about the user's terminal (depending on country, see www.bluevia.com)

        @return: (tuple): (HTTP status, (dict) userTerminalInfo). HTTP status == "200" for success. 
        """

        return self._getInfo("/UserTerminalInfo", "userTerminalInfo")
    

# # # # # # # # # # # # # # # # 
# Location Class
# # # # # # # # # # # # # # # # 

class BlueViaLocation(BlueVia):
    """
    The BlueVia class for retrieving user's terminal cell location.
    """

    def __init__(self, sandbox = "_Sandbox", realm = "BlueVia", version="v1"):
        """
        Initialize the BlueViaLocation object
        
        @param sandbox: (string): Indicates whether testing should be done in Sandbox mode. Use "" for real network access; Default: "_Sandbox"
        @param realm: (string): Realm string; Default: "BlueVia"
        @param version: (string): BlueVia API version; Default: "v1"
        """
                
        self.environment = sandbox
        self.realm = realm
        self.version = version
        self.location_url   = "https://api.bluevia.com/services/REST/Location%s/TerminalLocation"
    

    def locateTerminal(self, accuracy=None):
        """
        Retrieve the cell location of user's terminal (mobile device) including accuracy information
        
        Parameter:
        @param accuracy: (int): Provide neccessary accurracy. Returns an error if accuracy requirements are not met. 
        
        @return: (tuple):        (HTTP status, (dict) locationData). HTTP status == "200" for success.
        """
        
        assert self.hasCredentials(), "load oAuth credentials first or execute oAuth Dance"

        url = self.location_url % (self.environment)
        parameters = {"version":self.version, "alt":"json", "locatedParty":"alias:" + self.access_token.key }
        if accuracy:
            parameters["acceptableAccuracy"] = str(accuracy)
        response, content = self._signAndSend(url, "GET", self.access_token, parameters=parameters)
        if response["status"] == '200':
            return int(response["status"]), simplejson.loads(content)
        else:
            return int(response["status"]), content     
    
        
        
# # # # # # # # # # # # # # # # 
# Advertising Class
# # # # # # # # # # # # # # # # 

class BlueViaAds(BlueVia):
    """
    The BlueVia class for receiving BlueVia ads.
    """
    
    def __init__(self, adspaceId, sandbox = "_Sandbox", realm = "BlueVia", version="v1"):
        """
        Initialize the BlueViaAds object
        
        @param adspaceId:   The BlueVia ad space id provide during BlueVia app generation
        @param sandbox: (string): Indicates whether testing should be done in Sandbox mode. Use "" for real network access; Default: "_Sandbox"
        @param realm: (string): Realm string; Default: "BlueVia"
        @param version: (string): BlueVia API version; Default: "v1"
        """
        
        assert type(adspaceId) is StringType and adspaceId!= "", "'adspaceId' must be a non empty string"
        
        self.environment = sandbox
        self.realm = realm
        self.version = version
        self.adspaceId = adspaceId
        self.simple_ads_url = "https://api.bluevia.com/services/REST/Advertising%s/simple/requests"
    

    def getAd_2l(self, country, targetUserId=None, textAd=False, userAgent='none', keywordList=None, protectionPolicy=1):
        """
        Get ads without user authorization (2-legged oAuth)
        
        @param country: (string):       User's country in standard abbreviation, e.g. "UK" 
        
        @param targetUserId: (string):  Unique id to avoid users to be presented with the same Ad several times. Default: None, 
        @param textAd: (string):        If true requestes text ads, else image ads; efault is False 
        @param userAgent: (string):     Allows BlueVia advertising service to return the more appropiate size. Default: 'none' (and not python None) 
        @param keywordList: (array):    Get an ad related to some topics (e.g. 'computer|laptop'). Default: None, 
        @param protectionPolicy: (int): 1: Low, moderately explicit content 2:Safe, not rated content 3:High, explicit content. Default: 1

        @return: (tuple):                (HTTP status, (dict) advertisingData). HTTP status == "201" for success.
        """
        
        assert type(country) is StringType and country!= "", "'country' must be a non empty string"

        return self._getAd(None, country, targetUserId, textAd, userAgent, keywordList, protectionPolicy)
    

    def getAd_3l(self, textAd=False, userAgent='none', keywordList=None, protectionPolicy=1):
        """
        Get ads without user authorization (2-legged oAuth)
        
        @param textAd: (string):        If true requestes text ads, else image ads; efault is False 
        @param userAgent: (string):     Allows BlueVia advertising service to return the more appropiate size. Default: 'none' (and not python None) 
        @param keywordList: (array):    Get an ad related to some topics (e.g. 'computer|laptop'). Default: None, 
        @param protectionPolicy: (int): 1: Low, moderately explicit content 2:Safe, not rated content 3:High, explicit content. Default: 1

        @return: (tuple):                (HTTP status, (dict) advertisingData). HTTP status == "201" for success.
        """

        assert self.hasCredentials(), "load oAuth credentials first or execute oAuth Dance"

        return self._getAd(self.access_token, None, None, textAd, userAgent, keywordList, protectionPolicy)
    

    def _getAd(self, token, country, targetUserId, textAd, userAgent, keywordList, protectionPolicy):
        """
        Internal method
        """
        
        parameters = {}
        parameters["ad_request_id"] = str(uuid.uuid4()) + time.asctime() 
        if textAd:
            parameters["ad_presentation"] = '0104'
        else:
            parameters["ad_presentation"] = '0101'
        if country:
            parameters["country"] = country
        if targetUserId:
            parameters["target_user_id"] = targetUserId

        parameters["ad_space"] = self.adspaceId
        parameters["user_agent"] = userAgent
        if keywordList:
            parameters["keywords"] = "|".join(keywordList)
        parameters["protection_policy"] = protectionPolicy

        # exclude version parameter from body
        body = urllib.urlencode(parameters)
        
        parameters["version"] = self.version

        response, content = self._signAndSend(self.simple_ads_url % self.environment, "POST", token, \
                                              parameters=parameters, body=body, is_form_encoded=True, \
                                              extraHeaders={"Content-Type":"application/x-www-form-urlencoded;charset=UTF8"})

        if response["status"] == '201':
            return (int(response["status"]), _parseAdResponse(content))
        else:
            return response, content
    
# # # # # # # # # # # # # # # # 
# Payment Class
# # # # # # # # # # # # # # # # 

class BlueViaPayment(BlueViaOauth):
    """
    The BlueVia class for payments.
    """

    def __init__(self, consumer_key, consumer_secret, sandbox = "_Sandbox", realm = "BlueVia", version="v1"):
        """
        Initialize the BlueViaPayment object

        @param consumer_key: (string):     Key of the Consumer Credentials
        @param consumer_secret: (string):  Secret of the Consumer Credentials
        @param sandbox: (string): Indicates whether testing should be done in Sandbox mode. Use "" for real network access; Default: "_Sandbox"
        @param realm: (string):   Realm string; Default: "BlueVia"
        @param version: (string): BlueVia API version; Default: "v1"
        """
        
        BlueViaOauth.__init__(self, consumer_key, consumer_secret)
        self.environment = sandbox
        self.realm = realm
        self.version = version        
        self.payment_url   = "https://api.bluevia.com/services/RPC/Payment%s/payment"
        self.payment_status_url   = "https://api.bluevia.com/services/RPC/Payment%s/getPaymentStatus"
        self.payment_cancel_url   = "https://api.bluevia.com/services/RPC/Payment%s/cancelAuthorization"

    def fetch_request_token(self, amount, currency, serviceId, serviceName, callback="oob"):
        """
        First call of the Payment oAuth Dance. Provide the Consumer Credential and request the one time Request Token
        (Override of BlueViaOauth fetch_request_token method)

        @param amount: (string):      Price in the form 125 for 1.25
        @param currency: (string):    Currency, e.g. "EUR", "GBP"
        @param serviceId: (string):   Product identifier provided by our Mobile Payments Partner (sandbox: free choice)
        @param serviceName: (string): Product name as registered at our Mobile Payments Partner (sandbox: free choice)
        @param callback: (string):    The callback URL or "oob". Default: "oob"

        @return: (tuple):             (HTTP status, authorization URL). HTTP status == "200" for success
        """

        assert type(amount) is IntType and amount > 0, "'amount' must be an Integer > 0"
        assert type(currency) is StringType and currency!= "", "'currency' must be a non empty string"
        assert type(serviceId) is StringType and serviceId!= "", "'serviceId' must be a non empty string"
        assert type(serviceName) is StringType and serviceName!= "", "'serviceName' must be a non empty string"

        self.amount = amount
        self.currency = currency
        self.serviceId = serviceId
        self.serviceName = serviceName
        self.correlator = str(uuid.uuid4())
         
        paymentInfo = {"paymentInfo.currency":currency, "paymentInfo.amount":amount}
        serviceInfo = {"serviceInfo.name":serviceName, "serviceInfo.serviceID":serviceId}

        parameters={"oauth_callback":callback, "xoauth_apiName":"%s%s" % ("Payment",self.environment)}
        parameters.update(paymentInfo)
        parameters.update(serviceInfo)

        body = "%s&%s" % (urllib.urlencode(paymentInfo), urllib.urlencode(serviceInfo))
        body = body.replace("+", "%20")
        
        response, content = self._signAndSend(self.request_token_url, "POST", None, \
                                              parameters=parameters, \
                                              body=body, is_form_encoded=True, \
                                              extraHeaders={"Content-Type":"application/x-www-form-urlencoded;charset=UTF8"})
        if response["status"] == '200':
            self.request_token = oauth.Token.from_string(content)
            return int(response["status"]), "%s?oauth_token=%s" % (self.authorization_url, self.request_token.key)
        else:
            return int(response["status"]), content


    def savePaymentInfo(self, path):
        """
        Save Access Token and payment info (amount, currency, serviceId, serviceName, correlator)
        Will be valid for 48h only!
        
        Note: Unencrypted storage. Use only during development

        @param path: (string): Path to file on disk (pickle file)
        """

        assert type(path) is StringType and path!= "", "'path' must be a non empty string"

        fd = open(path, "w")
        data = (self.consumer, self.access_token, self.amount, self.currency, \
                self.serviceId, self.serviceName, self.correlator)
        pickle.dump(data, fd)
        fd.close()


    def loadPaymentInfo(self, path):
        """
        Load Access Token and payment info (amount, currency, serviceId, serviceName, correlator)

        @param path: (string): Path to file on disk (pickle file)
        """

        assert type(path) is StringType and path!= "", "'path' must be a non empty string"

        if os.path.exists(path):
            fd = open(path, "r")
            self.consumer, self.access_token, self.amount, self.currency, \
                           self.serviceId, self.serviceName, self.correlator = pickle.load(fd)
            fd.close()
            return True
        else:
            return False


    def issuePayment(self):   
        """
        Issue the actual payment with amount, currency, serviceId, serviceName given by fetch_request_token method

        @return: (tuple):              (HTTP status, (dict) paymentStatus). HTTP status == "200" for success.          
        """
        assert self.hasCredentials(), "load oAuth credentials first or execute oAuth Dance"
        assert type(self.amount) is IntType and self.amount > 0, "'amount' must be an Integer > 0"
        assert type(self.currency) is StringType and self.currency!= "", "'currency' must be a non empty string"

        p = {"methodCall": {
              "id": self.correlator,
              "version": self.version,
              "method": "PAYMENT",
              "params": { "paymentParams": {"paymentInfo": { "amount": str(self.amount),
                                                             "currency": self.currency  },
                                            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ") } }
            }}
        body = simplejson.dumps(p)

        response, content = self._signAndSend(self.payment_url % self.environment, "POST", self.access_token, \
                                              parameters={}, body=body, \
                                              extraHeaders={"Content-Type":"application/json;charset=UTF8"})
        if response["status"] == '200':
            return int(response["status"]), simplejson.loads(content)
        else:
            return int(response["status"]), content
        

    def checkPayment(self, transactionId):
        """
        Check the Payment status (polling)
        
        @param transactionId: (string): Transaction Id provided by issuePayment method

        @return: (tuple):              (HTTP status, (dict) paymentStatus). HTTP status == "200" for success.          
        """
        
        assert self.hasCredentials(), "load oAuth credentials first or execute oAuth Dance"
        assert type(transactionId) is StringType and transactionId!= "", "'transactionId' must be a non empty string"

        p = {"methodCall": {
              "id": self.correlator,
              "version": self.version,
              "method": "GET_PAYMENT_STATUS",
              "params": { "getPaymentStatusParams": { "transactionId": transactionId} }
        }}
        
        body = simplejson.dumps(p)
 
        response, content = self._signAndSend(self.payment_status_url % self.environment, "POST", self.access_token, \
                                              parameters={}, body=body, \
                                              extraHeaders={"Content-Type":"application/json;charset=UTF8"})

        if response["status"] == '200':
            return int(response["status"]), simplejson.loads(content)
        else:
            return int(response["status"]), content       


    def cancelPayment(self, correlator):
        """
        Check the Payment status (polling)

        @param correlator: (string): correlator provided by issuePayment method

        @return: (tuple):            (HTTP status, (dict) paymentStatus). HTTP status == "200" for success.          
        """

        assert self.hasCredentials(), "load oAuth credentials first or execute oAuth Dance"
        assert type(correlator) is StringType and correlator!= "", "'correlator' must be a non empty string"

        p = {"methodCall": {
              "id": self.correlator,
              "version": self.version,
              "method": "CANCEL_AUTHORIZATION"
        }}

        body = simplejson.dumps(p)

        response, content = self._signAndSend(self.payment_cancel_url % self.environment, "POST", self.access_token, \
                                              parameters={}, body=body, \
                                              extraHeaders={"Content-Type":"application/json;charset=UTF8"})

        if response["status"] == '200':
            return int(response["status"]), simplejson.loads(content)
        else:
            return int(response["status"]), content       
        