#!/bin/env python3
# Usage: ./download_latest_rpm.py os_type os_major destination_directory
# example to download Centos8's RPM: ./download_latest_rpm.py RHEL/CentOS/Oracle 8 /tmp/
from urllib.parse import urlencode
from urllib.request import Request, urlopen, urlretrieve
import sys
import time
import os
import json

# supply your api oauth token here
client=""
secret=""


try:
  ostype=sys.argv[1]
except:
  print("Define os type as given by Crowdstrike (ie: SLES, RHEL/CentOS/Oracle) as arg 1")
  exit(84)

try:
  osmaj=sys.argv[2]
except:
  print("Define os major release (7, 8) as arg 2")
  exit(87)

try:
  dest=sys.argv[3]
except:
  print("Define a destination directory for the download as arg 3.")
  exit(99)

if not os.path.exists(dest):
  print("Directory "+dest+" doesn't exist. Quitting.")
  exit(65)

baseurl="https://api.crowdstrike.com"
suburl="/oauth2/token"

def post2url(url,post_fields):
  request = Request(url, urlencode(post_fields).encode())
  jsondata = urlopen(request).read().decode()
  return json.loads(jsondata)

def postwheaders(url,headers):
  request = Request(url, headers=headers)
  jsondata = urlopen(request).read().decode()
  return json.loads(jsondata)
post_fields = {'client_id': client, 'client_secret':secret}     # Set POST fields here

myjson=post2url(baseurl+suburl,post_fields)
mytoken=myjson['access_token']

# Acquire bearer token for subsequent operations
bearer="Bearer "+mytoken
headers={'Authorization': bearer}
myurl="https://api.crowdstrike.com/sensors/combined/installers/v1?filter=os:'"+ostype+"'"
junk=postwheaders(myurl,headers)

# Set our starting date in the past for comparisons
newestdate="2017-04-23T22:08:44.032Z"

besthash=""
tofile=""
for item in junk["resources"]:
  newdate1 = time.strptime(newestdate.split("T")[0], "%Y-%m-%d")
  if item["os_version"]!=osmaj:
    continue
  # check our dates are newer than weird past date invented
  newdate2 = time.strptime(item["release_date"].split("T")[0], "%Y-%m-%d")
  if newdate2>newdate1:
    newestdate=item["release_date"]
  else:
    continue
  besthash=item["sha256"]
  tofile=item["name"]
  print("Plausible item:"+str(item))
if besthash=="":
  print("Couldn't find a plausible hash from the site. Exiting")
  sys.exit(66)


# hash acquired, download it from url
print("Attempting to download hash "+besthash)
url='https://api.crowdstrike.com/sensors/entities/download-installer/v1?id='+besthash
getfile=Request(url, headers=headers)

with open(dest+'/'+tofile, 'b+w') as f:
  print("Downloading... ")
  f.write(urlopen(getfile).read())
print("Done! File available at "+dest+'/'+tofile)

# Check the sha256 hash of our local copy matches what's expected
import hashlib
print("Checking hashes...") 
with open(dest+'/'+tofile,"rb") as f:
    bytes = f.read() # read entire file as bytes
    readable_hash = hashlib.sha256(bytes).hexdigest();
if readable_hash==besthash:
  print("Hash on file matches what we wanted to download.")
else:
  print("ERROR: Hash on file doesn't match what we wanted to download. Downloaded="+readable_hash+" vs expected="+besthash)
  sys.exit(65)
