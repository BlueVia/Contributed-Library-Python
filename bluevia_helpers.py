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



# # # # # # # # # # # # # # # # 
# Simple XML to JSON Class
# # # # # # # # # # # # # # # #

from xml.dom.minidom import parseString

def _parseAdResponse(xmlString): 
    """
    Parses the XML respponse of a BlueVia Adsvertising requests and constructs a JSON object as result 
    
    Internal method
    """
    
    dom = parseString(xmlString)
    arId       = dom.getElementsByTagName ("NS1:adResponse")[0].attributes.getNamedItem("id").value
    arVersion  = dom.getElementsByTagName ("NS1:adResponse")[0].attributes.getNamedItem("version").value
    adId       = dom.getElementsByTagName ("NS1:ad")[0].attributes.getNamedItem("id").value
    adPlace    = dom.getElementsByTagName ("NS1:ad")[0].attributes.getNamedItem("ad_placement").value
    adCampaign = dom.getElementsByTagName ("NS1:ad")[0].attributes.getNamedItem("campaign").value
    adFlight   = dom.getElementsByTagName ("NS1:ad")[0].attributes.getNamedItem("flight").value
    adPresent  = dom.getElementsByTagName ("NS1:resource")[0].attributes.getNamedItem("ad_presentation").value
    ce         = dom.getElementsByTagName ("NS1:creative_element")[0]
    ceType     = ce.attributes.items()[0]
    ceAttrs    = [(n.attributes.items(), n.childNodes[0].nodeValue) for n in ce.childNodes if n.nodeName == "NS1:attribute"]
    ceInter    = dom.getElementsByTagName ("NS1:interaction")[0]
    ciType     = ceInter.attributes.items()[0]
    ciAttrs    = [(n.attributes.items(), n.childNodes[0].nodeValue) for n in ceInter.childNodes if n.nodeName == "NS1:attribute"]


    creativeElement = {
        ceType[0]:ceType[1],
        "attributes":[{x[0][0][0]:x[0][0][1],"value":x[1]} for x in ceAttrs],
        "interaction":{ciType[0]:ciType[1],
                       "attributes":[{x[0][0][0]:x[0][0][1],"value":x[1]} for x in ciAttrs]}
    }
    fullAd = {"adResponse": { \
                 "id":arId, \
                 "version":arVersion, \
                 "ad": { \
                    "id":adId, \
                    "ad_place_ment":adPlace, \
                    "campaign":adCampaign, \
                    "flight":adFlight, \
                    "resource":{ \
                        "ad_representation":adPresent, \
                        "creative_element": creativeElement}}}}
    return fullAd


# # # # # # # # # # # # # # # # 
# Simple Multipart POST body
# # # # # # # # # # # # # # # #

import random, string, sys, mimetypes, base64, email, os

def _random_string (length):
    return ''.join (random.choice (string.letters) for ii in range (length + 1))

def _encodeMultipart (root, messages = None, files = None):
    """
    Encodes messages and files in Multipart MIME format fitting for BlueVia Send MMS API 
    
    Internal method
    """
    
    # to comply with blueVia format, some adaptation to email.mime.multipart results would have to be applied
    # so just do it manually
    boundary1 = _random_string (32)
    boundary2 = _random_string (32)

    def get_content_type (filename):
        return mimetypes.guess_type (filename)[0] or 'application/octet-stream'

    def encode_message (num, message, boundary):
        return ('--' + boundary,
                'Content-Disposition: attachment; name="message%d.txt"' % num,
                'Content-Type: text/plain',
                'Content-Transfer-Encoding: 8bit;charset=UTF-8',
                '', str(message))

    def encode_file (field_name, boundary):
        filename = files [field_name]
        return ('\r\n--' + boundary,
                'Content-Disposition: attachment; filename="%s"' % filename,
                'Content-Type: %s' % get_content_type(filename),
                'Content-Transfer-Encoding: base64',
                '', base64.encodestring(open (filename, 'rb').read ()))
                
    lines = ['\r\n--' + boundary1,
            'Content-Disposition: form-data; name="root-fields"',
            'Content-Type: application/json;charset=UTF-8',
            'Content-Transfer-Encoding: 8bit',
            '', str(root)]

    if messages or files:
        att =  ('\r\n--' + boundary1,
                'Content-Disposition: form-data; name="attachments"',
                'Content-Type: multipart/mixed; boundary=%s' % boundary2,
                '')
        lines.extend(att)

    if messages:
        i=0
        for msg in messages:
            lines.extend (encode_message(i, msg, boundary2))
            i += 1
    if files:
        for name in files:
            lines.extend (encode_file (name, boundary2))

    lines.extend (('--%s--' % boundary2, ''))
    lines.extend (('--%s--' % boundary1, ''))
    body = '\r\n'.join (lines)

    headers = {'content-type': 'multipart/form-data; boundary=' + boundary1,
               'content-length': str (len (body))}

    return body, headers
    
def _decodeMultipart(msgId, body):
    """
    Decodes the BlueVia Multipart MIME body from retrieving MMS attachemnts into a folder with message and file objects 
    
    Internal method
    """
    
    common_ext = {  'image/jpg': '.jpg',
                    'image/jpeg': '.jpg',
                    'image/png': '.png',
                    'application/json': '.json',
                    'application/xml': '.xml',  
                    'text/plain': '.txt',
                    'text/html': '.html'
    }

    result = []
    directory = msgId
    os.mkdir(directory)
    
    # add the multipart header, unfortunately missing in BlueVia response
    boundary = body[:200].split("\r\n")[1][2:]
    fullbody = 'Content-Type: multipart/mixed; boundary="%s"\r\n%s\r\n"' % (boundary, body)
    
    msg = email.message_from_string(fullbody)
    counter = 1
    for part in msg.walk():
        # multipart/* are just containers
        if part.get_content_maintype() == 'multipart':
            continue
        filename = part.get_filename()
        ext = common_ext.get(part.get_content_type())
        if not ext:
            ext = mimetypes.guess_extension(part.get_content_type())
            if not ext:
                ext = '.bin'
        if filename:
            if not os.path.splitext(filename)[1]:
                filename += ext
        else:
            filename = 'part-%03d%s' % (counter, ext)
            counter += 1

        fp = open(os.path.join(directory, filename), 'wb')
        fp.write(part.get_payload(decode=True))
        fp.close()
        
    print "%d files saved to %s" % (counter, msgId)
    return (counter, msgId)
    