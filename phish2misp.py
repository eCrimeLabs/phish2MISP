#!/usr/bin/python3
"""
MIT License

Copyright (c) 2020 Dennis Rand (https://www.ecrimelabs.com)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import re
import sys
import os
import socket
import dns.resolver
import requests
import argparse
import string
import time
import base64
from io import BytesIO
import hashlib
import pprint
import json
import tldextract
from pymisp import ExpandedPyMISP, PyMISP, MISPObject, MISPEvent
from keys import misp_url, misp_key, proxies, misp_verifycert, misp_tags, make_screenshot, auto_publish, misp_distribution, misp_threat_level_id, misp_analysis, sharing_group_id

#pymisp = ExpandedPyMISP(misp_url, misp_key, misp_verifycert, debug=False, proxies=proxies)
pymisp = PyMISP(misp_url, misp_key, misp_verifycert, debug=False, proxies=proxies)
headers = {"User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36"}
user_agent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36"
def splash():
    print ('Phishing to MISP')
    print ('(c)2020 eCrimeLabs')
    print ('https://www.ecrimelabs.com')
    print ("----------------------------------------\r\n")

def create_screenshoot(phish_url, phish_subdomain):
    file_name = "/tmp/" + phish_subdomain + ".png"
    tries = 3
    delay = 2
    print ("\t- Collecting screenshot of phishing URL")
    # http://cutycapt.sourceforge.net/
    screen_collect = 'xvfb-run --server-args="-screen 0, 1024x2550x24" cutycapt --url=' + phish_url + ' --min-width=1366 --min-height=1600 --user-agent="' + user_agent + '" --out=' + file_name
    for i in range(tries):
        os.system(screen_collect)
        if os.path.exists(file_name):
            return(file_name)

        print("\t    Failed to collect screenshoot - Retry {}/{}".format(i, tries))
        time.sleep(delay) # Adding a small delay
    print ("\t- Screenshot of Phishing site failed\r\n\r\nTerminating collection")
    sys.exit(1)


def collect_phish_artefacts(phish_domain, phish_subdomain, phish_url, phish_target):
    phish_artefacts = {}
    phish_artefacts['phish_domain'] = phish_domain
    phish_artefacts['phish_subdomain'] = phish_subdomain
    phish_artefacts['phish_url'] = phish_url
    phish_artefacts['phish_target'] = phish_target

    print ("\t- Collecting IP(s) for phishing domain: " + phish_subdomain)
    try:
        data = socket.gethostbyname_ex(phish_subdomain)
        phish_artefacts['ips'] = data[2]
    except Exception:
        phish_artefacts['ips'] = []

    print ("\t- Collecting Nameservers for phishing domain: " + phish_domain)
    try:
        ns = dns.resolver.query(phish_domain,'NS')
        domain_names = []
        for i in ns.response.answer:
            for j in i.items:
                domain_names.append(j.to_text())
        phish_artefacts['ns'] =  domain_names
    except Exception:
        phish_artefacts['ns'] = []

    if not phish_artefacts['ips']:
        print ("\t- Phishing domain did not resolve to IP(s)\r\n\r\nTerminating collection")
        sys.exit(1)

    if (make_screenshot):
        file_name = create_screenshoot(phish_url, phish_subdomain)
        phish_artefacts['screenshot'] = file_name

    return(phish_artefacts)

def misp_create_objects(event, phish_artefacts):
    try:
        misp_obj = MISPObject(name='phishing', standalone=False)
        if (make_screenshot):
            with open(phish_artefacts['screenshot'], 'rb') as f:
                misp_obj.add_attribute('screenshot', value=phish_artefacts['phish_subdomain'] + '.png', data=BytesIO(f.read()), expand='binary')
        misp_obj.add_attribute(object_relation='url', value=phish_artefacts['phish_url'])
        misp_obj.add_attribute(object_relation='hostname', value=phish_artefacts['phish_subdomain'])
        misp_obj.add_attribute(object_relation='target', value=phish_artefacts['phish_target'])
        phishing_object = event.add_object(misp_obj)

        misp_obj = MISPObject(name='domain-ip', standalone=False)
        misp_obj.add_attribute(object_relation='domain', value=phish_artefacts['phish_subdomain'])
        for ip in phish_artefacts['ips']:
           misp_obj.add_attribute(object_relation='ip', value=ip)
        domain_ip_object = event.add_object(misp_obj)

        misp_obj = MISPObject(name='whois', standalone=False)
        misp_obj.add_attribute(object_relation='domain', value=phish_artefacts['phish_domain'], disable_correlation=True, to_ids=False)
        for ip in phish_artefacts['ips']:
           misp_obj.add_attribute(object_relation='ip-address', value=ip, disable_correlation=True, to_ids=False)
        for nameserver in phish_artefacts['ns']:
            misp_obj.add_attribute(object_relation='nameserver', value=nameserver, disable_correlation=False, to_ids=False)
        whois_object = event.add_object(misp_obj)

        # Createing references between the objects
        domain_ip_object.add_reference(referenced_uuid=phishing_object.uuid, relationship_type='related-to', comment='')
        whois_object.add_reference(referenced_uuid=phishing_object.uuid, relationship_type='related-to', comment='')
    except:
        print ("Error: Failed to create objects ... Terminated")
        sys.exit(1)


def misp_event_exists_check(internal_reference):
    response = pymisp.search(value=internal_reference, category='Internal reference', type='text' , pythonify=True)
    return(response)

def misp_event_create(event_info, internal_reference, phish_artefacts):
    event = MISPEvent()
    event.distribution = misp_distribution
    if(sharing_group_id >= 1 and misp_distribution == 4):
        event.sharing_group_id = sharing_group_id
    event.threat_level_id = misp_threat_level_id
    event.analysis = misp_analysis
    event.info = event_info
    event = pymisp.add_event(event, pythonify=True)
    if hasattr(event, 'uuid'):
        attribute = pymisp.add_attribute(event.uuid, {'type': 'text', 'value': internal_reference, 'category': 'Internal reference', 'distribution': "0"}, pythonify=True)
        if(attribute.value == internal_reference):
            # Creating Object
            print ("Creating Objects...")
            misp_create_objects(event, phish_artefacts)
            for misp_tag in misp_tags:
                pymisp.tag(event.uuid, misp_tag)
            pymisp.update_event(event)
        else:
            return("")
    if(auto_publish):
        print ("Publishing MISP Event")
        pymisp.publish(event)
    return(event)

if __name__ == '__main__':
    splash()
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", help="The URL of the phishing site (http://www.phishing.com/site.html)", required=True)
    parser.add_argument("-e", "--event", help="The event name to be created in MISP", required=True)
    parser.add_argument("-t", "--target", help="The name e.g. NemID", required=True)

    if len(sys.argv)==1:
    	parser.print_help(sys.stderr)
    	sys.exit(1)
    args = parser.parse_args()

    event_info = args.event
    phish_url = args.url
    phish_target = args.target
    internal_reference = hashlib.md5(phish_url.encode('utf-8')).hexdigest()

    ext = tldextract.extract(phish_url)
    phish_subdomain = '.'.join([ext.subdomain, ext.domain, ext.suffix])
    phish_domain = '.'.join([ext.domain, ext.suffix])

    # Check if the event exists else create it with magic reference
    response = misp_event_exists_check(internal_reference)
    if (len(response) >= 1):
        misp_event = response[0]
        event_uuid = misp_event.uuid
        print ("The phishing url: '" + phish_url + "' exists in your MISP instance\r\nUUID: " + event_uuid + "")
        sys.exit(0)
    else:
        print ("Collecting data from Phishing URL...")
        phish_artefacts = collect_phish_artefacts(phish_domain, phish_subdomain, phish_url, phish_target)
        print ("Creating MISP Event...")
        event_misp = misp_event_create(event_info, internal_reference, phish_artefacts)
        print ("MISP event created: " + event_misp.uuid)
