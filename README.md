# DeviceBlock
This Python script will take a list of Cylance policies, extract any device blocks by serial number, and import them back into your SentinelOne console.

# Quick Start
## API Requirements
- Cylance Tenant ID
- Cylance Application ID
- Cylance Application Secret
- SentinelOne API Token
## Module Requirements
- requests
- logging (only if you need to debug)
- json
- jwt
- uuid
- datetime
- tabulate
## Credits and Notes
The Cylance token generation is a modified version of the script provided by Cylance to generate a temporary token for authentication.  This token has a timeout typically, but a new working token will be generated every time you run the script. 

The automatic Cylance policy query doesn't fully work, so you must specificy the policy id's manaully in a global variable.  The query works fine, but it only pulls back five total policies due to paging. 
