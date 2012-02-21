Keywords:			MultiMarkdown, Markdown, XML, XHTML, XSLT, PDF   
CSS:				css/print.css
CSS:  				css/doc-less.css



Feel free to download and mess around with this app, it may or may not be updated regularly, when it is we will publicise on our twitter feed (@BlueVia)


## Get your Python environment prepared


There is little to do with python. The tutorial has been prepared with Python 2.6. Further on we need three additional python modules:

- [httplib2](http://code.google.com/p/httplib2/): Makes life with http calls easier
- [oauth2](https://github.com/simplegeo/python-oauth2): The actual oauth library
- [simplejson](http://code.google.com/p/simplejson): Makes life with JSON easier

The easiest way to get these is *easy_install*  from python setup tools:

		easy_install httplib2
		easy_install oauth2
		easy_install simplejson
	
	
## Sample usage of all BlueVia python routines


### Some personal settings

	
		myMobileNumber = "44xxxxxxxxxx"
	
		myShortcode = "445480605" # UK
		myAdSpaceId = "xxxxx"

		# App with all API's ticked 
		my3leggedConsumer = 'xxxxxxxxxxxxxxxx' #Your developer consumer key
		my3leggedSecret = 'xxxxxxxxxxxx' #Your developer consumer secret

		# App with advertising only
		my2leggedConsumer = 'xxxxxxxxxxxxxxxx'
		my2leggedSecret = 'xxxxxxxxxxxx'
	
### oAuth Dance

		import bluevia
		import webbrowser 
		
		o3 = bluevia.BlueViaOauth(my3leggedConsumer, my3leggedSecret)
		url = o3.fetch_request_token()[1]
		webbrowser.open(url) # Opens authorisation url in browser
		reqtok = str(raw_input("Enter pin code")) #asks for authorisation pin and saves it in variable
		o3.fetch_access_token(reqtok)
		o3.saveAccessToken(myMobileNumber + "_acctok.pk1")
		
### Send SMS and track delivery

		s = bluevia.BlueViaOutboundSms()
		s.loadAccessToken("token.pkl")
		r = s.sendSMS([myMobileNumber], "Hello BlueVia")
		s.deliveryStatus(r[1])

Note: to use the real radio network call (this holds for all BlueVia calless below):
		
		s = bluevia.BlueViaOutboundSms(sandbox="")

### Receive SMS (first send one or more SMS to the sandbox shortcode)

		s.sendSMS([shortcode], "SANDBWTUT01 BlueVia")

		si = bluevia.BlueViaInboundSMS()
		si.loadAccessToken("token.pkl")
		si.receiveSMS(shortcode)


### Send MMS

		m = bluevia.BlueViaOutboundMms()
		m.loadAccessToken("token.pkl")
		m.sendMMS(myMobileNumber, "Hello Multimedia BlueVia", \
				  ["Message\n Number 1", "Yet another\n Message"], \
				  ["samples/atextfile.txt", "samples/image.jpg"])

Receive MMS and retrieve the attachemnts (first send one or more MMS to the sandbox shortcode)

		m.sendMMS(myShortcode, "SANDBWTUT01 BlueVia Multimedia", \
				  ["Message\n Number 1", "Yet another\n Message"], \	
				  ["samples/atextfile.txt", "samples/image.jpg"])

		mi = bluevia.BlueViaInboundMMS()
		mi.loadAccessToken("token.pkl")
		r = mi.receiveMMS(myShortcode)
		mid = r[1]['receivedMessages']['messageIdentifier']
		mi.retrieveAttachments(myShortCode, mid)

### User Context API

		u = bluevia.BlueViaUserContext()
		u.loadAccessToken("token.pkl")
		u.getUserInfo()

### Location API

		l = bluevia.BlueViaLocation()
		l.loadAccessToken("token.pkl")
		l.locateTerminal()

### Advertising API (3 legged oAuth)

		a3 = bluevia.BlueViaAds(myAdSpaceId)
		a3.loadAccessToken("token.pkl")
		a3.getAd_3l()

### Advertising API (2 legged oAuth)

        import oauth2 as oauth
        a2 = bluevia.BlueViaAds(myAdSpaceId)
        a2.setConsumer(oauth.Token(	my2leggedConsumer, my2leggedSecret))
        a2.setDebug(debugFlag)
		a2.getAd_2l("GB")

### Payment API

        p = bluevia.BlueViaPayment(my3leggedConsumer, my3leggedSecret)
        amount      = 199       # no float, 199 means 1.99 EUR
        currency    = "EUR"     # EUR, GBP, ...

        # In sandbox any strings, commercially the service Id / Name given by the Mobile Payment Partner
        serviceId   = "123456"          
        serviceName = "My Digital Good" 

        p.fetch_request_token(amount, currency, serviceId, serviceName)

        # When finished copy verifier, e.g 176539
        p.fetch_access_token("176539")
        
        p.savePaymentInfo("payment.pkl") # optional, token valid for 48 h
        p.loadPaymentInfo("payment.pkl") # optional
        
        result = p.issuePayment()
        txid = result[1]["methodResponse"]["result"]["paymentResult"]["transactionId"]
        p.checkPayment(txid)

