#!/usr/bin/python

#--------------------------------------------- Meta ----------------------------------------------------------
# Purpose: Sync Cylance device Blocks to SentinelOne
# Author: OneEyedGlocer
# License: GNU General Public License v3.0

#---------------------------------------- Import Modules -----------------------------------------------------
import requests
import logging
import json
import jwt
import uuid
from datetime import datetime, timedelta
from tabulate import tabulate


#---------------------------------------- Logging Requests ---------------------------------------------------
#These two lines enable debugging at httplib level (requests->urllib3->http.client)
#You will see the REQUEST, including HEADERS and DATA, and RESPONSE with HEADERS but without DATA.
#The only thing missing will be the response.body which is not logged.
# try:
#    import http.client as http_client
# except ImportError:
#     #Python 2
#     import httplib as http_client
# http_client.HTTPConnection.debuglevel = 1

# #You must initialize logging, otherwise you'll not see debug output.
# logging.basicConfig()
# logging.getLogger().setLevel(logging.DEBUG)
# requests_log = logging.getLogger("requests.packages.urllib3")
# requests_log.setLevel(logging.DEBUG)
# requests_log.propagate = True


#---------------------------------------- Global Variables ---------------------------------------------------
''' Cylance Variables '''
cy_tenant_id = "ADD TENANT ID" # Cylance tenant's unique identifier
cy_app_id = "ADD CYLANCE APPLICATION UNIQUE IDENTIFIER" # Cylance application's unique identifier
cy_app_secret = "ADD CYLANCE APPLICATION SECRET" # Cylance application's secret to sign the auth token with
cy_policies = ['ADD POLICY ID,'ADD POLICY ID']
cy_api_host = "protectapi.cylance.com" # Cylance host based on geographic location (formatted for US)
cy_policyid_endpoint = "https://{0}/policies/v2/".format(cy_api_host) # Cylance policy api endpoint
''' SentinelOne Variables '''
s1_token = "ADD SENTINEL ONE API TOKEN" # SentinelOne api token
s1_headers = {'Accept-Encoding': 'application/json','Authorization': 'ApiToken {0} '.format(s1_token),'Content-Type': 'application/json'} # SentinelOne Headers
s1_api_host = "ADD SENTINEL ONE WEB CONSOLE URL" # SentinelOne tenant host
s1_devicecontrol_endpoint = "https://{0}/web/api/v2.1/device-control".format(s1_api_host) # SentinelOne device-control api endpoint
s1_account_id = "ACCOUNT SENTINEL ONE ACCOUNT ID" # SentinelOne account identifier (you can use also filter by site/group)


#-------------------------------------------------------------------------------------------------------------
#---------------------------------------------- Main  --------------------------------------------------------
#-------------------------------------------------------------------------------------------------------------


#----------------------------------- Get temporary Cylance token ---------------------------------------------
def getCylanceHeaders():
    timeout = 1800 # 30 minutes from now
    now = datetime.utcnow()
    timeout_datetime = now + timedelta(seconds=timeout)
    epoch_time = int((now - datetime(1970, 1, 1)).total_seconds())
    epoch_timeout = int((timeout_datetime - datetime(1970, 1, 1)).total_seconds())
    jti_val = str(uuid.uuid4())
    tid_val = "{0}".format(cy_tenant_id)
    app_id = "{0}".format(cy_app_id)
    app_secret = "{0}".format(cy_app_secret)
    AUTH_URL = "https://protectapi.cylance.com/auth/v2/token"
    claims = {
    "exp": epoch_timeout,
    "iat": epoch_time,
    "iss": "http://cylance.com",
    "sub": app_id,
    "tid": tid_val,
    "jti": jti_val
    }

    encoded = jwt.encode(claims, app_secret, algorithm='HS256').decode('utf-8')
    payload = {"auth_token": encoded}
    headers = {"Content-Type": "application/json; charset=utf-8"}
    resp = requests.post(AUTH_URL, headers=headers, data=json.dumps(payload))
    cylance_token = json.loads(resp.text)['access_token']
    cy_headers = { 'Accept': 'application/json', 'Authorization': 'Bearer '+ cylance_token}
    return cy_headers


#--------------------------------------- Get Cylance Policies -----------------------------------------------
''' Not working if you have more than 5 policies due to paging - manuall define policies above. '''
# def getCylancePolicies(cy_headers):
#     cy_policy_url = "https://protectapi.cylance.com/policies/v2?page=1&page_size=200"
#     payload = {}
#     response = requests.request("GET", cy_policy_url, headers=cy_headers, data = payload)
#     data = response.json()


#-------------------------- Get serial numbers from Cylance device control -----------------------------------
def getDeviceSerial(cy_policies, cy_headers):
    devicelist=[]
    for policy_id in cy_policies:
      policy_id.strip("'")
      url = "{0}{1}".format(cy_policyid_endpoint,policy_id)
      response = requests.request("GET", url, headers=cy_headers)
      policy_data = response.json()
      if 'device_control' in policy_data:
        devices = (policy_data)['device_control']['exclusion_list']
        for item in devices:
          serial_number = item['serial_number']
          if serial_number is not None:
            devicelist.append(serial_number)
    return devicelist


#--------------------------- Submit Cylance USB Block by Serial to S1 ----------------------------------------
def postSerialBlocks(devicelist):
    results=[]
    for serial in devicelist:
        serial = serial.strip("'")
        body = '{\"filter\": {\"accountIds\":\"'+s1_account_id+'\" },\"data\":{ \"deviceClass\":\"08h\",\"ruleType\":\"uid\",\"action\": \"Block\",\"ruleName\": \"Cylance import serial '+serial+ '\",\"interface\": \"USB\",\"uid\": \"'+serial+'\",\"status\": \"Disabled\"}}'
        req = requests.post(s1_devicecontrol_endpoint, headers=s1_headers, data=body, verify=False)
        r = req.json()
        data = [serial, r]
        for result in data:
          results.append(data)
    return results


#------------------------------------------ Print Results -----------------------------------------------------
def printResults(results):
    print(tabulate(results, ["Serial Number", "Results"], tablefmt="fancy_grid"))


def main():
    cy_headers = getCylanceHeaders()
    devicelist = getDeviceSerial(cy_policies, cy_headers)
    results = postSerialBlocks(devicelist)
    printResults(results)

if __name__ == '__main__':
        main()





