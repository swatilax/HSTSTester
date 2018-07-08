#!/usr/bin/env python2

# python standard library
import re, sys, urllib2, urlparse, argparse

# -------------------------------------------------------------------------------------------------

def usage():
  parser = argparse.ArgumentParser(description="Simple HSTS misconfigurations checker")
  parser.add_argument("infile", help="File with domain or URL list")
  return parser.parse_args()

# -------------------------------------------------------------------------------------------------

def main():
  
  global args; args = usage()
  try:
    urls = [line.rstrip() for line in open(args.infile)]
    for u in urls:
	check(u)
  except (IOError, ValueError) as e: print e; return

# check for misconfigurations
def check(url):
  if re.findall("^https://", url): 
	args.s = True     
  else:
	args.s = False 
  url = re.sub("^https?://", "", url)                
  host = urlparse.urlparse("//"+url).hostname or ""  # set hostname
  isHSTS(url, url, False)                 # perform request


# perform request and fetch response header
def isHSTS(url, origin, ssltest=False):
  url = ("http://" if not (ssltest or args.s) else "https://") + url
  # if url is http, we need to check if the server has http to https redirect
  print "------------------\nProcessing url %s\n------------------\n" % (url)
  try:
    request = urllib2.Request(url)
    response = urllib2.urlopen(request)#, timeout=10)
    final_url = response.geturl()
    if final_url != url:
	request = urllib2.Request(final_url)
    	response = urllib2.urlopen(request)
    hsts_info = response.info()
    hsts = hsts_info.getheader('Strict-Transport-Security')
    if hsts is None:
	print "HSTS not set up for the url %s" % (url)
	return
    hsts_elements = re.split(";", hsts)
    results_good = ""
    results_bad = ""
    if any('includeSubdomains' in hsts_element for hsts_element in hsts_elements):
	results_good += "includeSubDomains set for the url : %s\n" % (url)
    else:
	results_bad  += "includeSubDomains not set for the url : %s\n" % (url)
    
    if "max-age" in hsts:
	results_good += "max-age set for the url : %s\n" % (url)
    else:
	results_bad  += "max-age not set for the url : %s\n" % (url)

    if "preload" in hsts:
	results_good += "preload set for the url : %s\n" % (url)
    else:
	results_bad  += "preload not set for the url : %s\n" % (url)

    print "Proper configuration listed below for url: %s:" % (url)
    print results_good
    print "Bad configuration listed below: %s:" % (url)
    print results_bad
  
  except Exception as e:
    print "Error while processing the url %s : %w!!" % (url,e)
    return

if __name__ == '__main__':
  main()
