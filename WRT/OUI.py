import urllib2
import json
import codecs


def get_vendor(mac_address):
    #API base url,you can also use https if you need
    url = "http://macvendors.co/api/"
    #Mac address to lookup vendor from

    request = urllib2.Request(url+mac_address, headers={'User-Agent' : "API Browser"}) 
    response = urllib2.urlopen( request )
    #Fix: json object must be str, not 'bytes'
    reader = codecs.getreader("utf-8")
    obj = json.load(reader(response))
    print obj
    #Print company name
    if 'company' in obj['result']:
        print(mac_address + "\t" + obj['result']['company'])
    else:
        print(mac_address)


get_vendor("08:02:8e:2b:24:b4")