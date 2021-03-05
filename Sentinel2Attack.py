import yaml
import json
import os
import requests

Local_Path = "Queries/" # Change it to where you store your local Yaml queries 

Azure_AD_Tenant = "Azure_AD_Tenant_HERE"
Client_ID = "Client_ID_HERE"
Client_Secret = "Client_Secret_HERE"
ResourceGroup = "ResourceGroup_HERE"
Workspace = "Workspace_HERE"
Subscription = "Subscription_ID"


Local_Queries = []
Github_hunt = []
Github_detect = []
SentinelHunt_Queries = []
Sentinel_Detections = []
Sentinel_Alerts = []

# Get list of Techniques from a local repository

Raw_queries  = [pos_raw for pos_raw in os.listdir(Local_Path) if pos_raw.endswith('.yaml')]
for query in Raw_queries:
    #print(query)
    with open(Local_Path+query,'r',encoding='utf-8') as q: #errors='ignore' 
        yaml_query = yaml.load(q, Loader=yaml.FullLoader)        
    try:
        for j in range(len(yaml_query["relevantTechniques"])): 
            #print(yaml_query["relevantTechniques"][j])
            if yaml_query["relevantTechniques"][j] not in Local_Queries:
                Local_Queries.append(yaml_query["relevantTechniques"][j])
        
    except KeyError:
             pass

print("[+] Techniques were extracted from Local Queries Successfully")

#Get list of techniques from the official Azure Sentinel Github repositories 

# Clone the official Azure Sentinel Repository from Github
Azure_Sentinel_repo = "https://github.com/Azure/Azure-Sentinel"
os.system("git clone "+Azure_Sentinel_repo)
print("[+] Azure Sentinel Repository was cloned Successfully")


#Get techniques from Github Hunining queries

Github_Detections = [ name for name in os.listdir("Azure-Sentinel/Detections") if os.path.isdir(os.path.join("Azure-Sentinel/Detections", name))]
Github_Hunting = [ name for name in os.listdir("Azure-Sentinel/Hunting Queries") if os.path.isdir(os.path.join("Azure-Sentinel/Hunting Queries", name)) ]

for p in Github_Hunting:
    for hunt in [pos_raw for pos_raw in os.listdir("Azure-Sentinel/Hunting Queries/"+p) if pos_raw.endswith('.yaml')]:
        #print(hunt)
        with open("Azure-Sentinel/Hunting Queries/"+p+"/"+hunt,'r',encoding='utf-8',errors='ignore') as h:
            hunt_query = yaml.load(h, Loader=yaml.FullLoader) 
        try:
            for z in range(len(hunt_query["relevantTechniques"])):
                if hunt_query["relevantTechniques"][z] not in Github_hunt:
                    Github_hunt.append(hunt_query["relevantTechniques"][z])
        except KeyError:
            pass

print("[+] Techniques were extracted from Azure Sentinel Github Hunting Queries Successfully")

# Get techniques from Github Detections

for D in Github_Detections:
    for detect in [pos_raw for pos_raw in os.listdir("Azure-Sentinel/Detections/"+D) if pos_raw.endswith('.yaml')]:
        #print(detect)
        with open("Azure-Sentinel/Detections/"+D+"/"+detect,'r',encoding='utf-8',errors='ignore') as f:
            detect_query = yaml.load(f, Loader=yaml.FullLoader) 
                   
        try:
            if type(detect_query["relevantTechniques"]) in (list,tuple,dict, str):
                for d in range(len(detect_query["relevantTechniques"])):
                    if detect_query["relevantTechniques"][d] not in Github_detect:
                        Github_detect.append(detect_query["relevantTechniques"][d])
        except KeyError:
            pass
        
print("[+] Techniques were extracted from Azure Sentinel Github Detections Successfully")

# Get list of techniques from Azure Sentinel

# Get Hunting Rules

Url = "https://login.microsoftonline.com/"+Azure_AD_Tenant+"/oauth2/token"
headers = {'Content-Type': 'application/x-www-form-urlencoded'}
payload='grant_type=client_credentials&client_id='+ Client_ID+'&resource=https%3A%2F%2Fmanagement.azure.com&client_secret='+Client_Secret
response = requests.post(Url, headers=headers, data=payload).json()
Access_Token = response["access_token"]
print("[+] Access Token Received Successfully")

Url2= "https://management.azure.com/subscriptions/"+Subscription+"/resourceGroups/"+ResourceGroup+"/providers/Microsoft.OperationalInsights/workspaces/"+Workspace+"/savedSearches?api-version=2020-08-01"
Auth = 'Bearer '+Access_Token
headers2 = {
  'Authorization': Auth ,
  'Content-Type': 'text/plain'
}

response2 = requests.get(Url2, headers=headers2).json()
print("[+] Hunting Query Details were received from Azure Sentinel Successfully")


for t in range(len(response2["value"])):
    try:
        if str(response2["value"][t]["properties"]["Category"]) == "Hunting Queries":
            if (str(response2["value"][t]["properties"]["DisplayName"]).split()[0][0]== "T"):
                SentinelHunt_Queries.append(str(response2["value"][t]["properties"]["DisplayName"]).split()[0])

    except KeyError:
             pass

print("[+] Techniques were extracted from your Azure Sentinel Hunting Queries Successfully")

# Get Sentinel Alert Rules

Url3= "https://management.azure.com/subscriptions/"+Subscription+"/resourceGroups/"+ResourceGroup+"/providers/Microsoft.OperationalInsights/workspaces/"+Workspace+"/providers/Microsoft.SecurityInsights/alertRules?api-version=2020-01-01"
Auth = 'Bearer '+Access_Token
headers2 = {
  'Authorization': Auth ,
  'Content-Type': 'text/plain'
}

response3 = requests.get(Url3, headers=headers2).json()
print("[+] Alert Rules Details were received Successfully")

for a in range(len(response3["value"])):
    if (str(response3["value"][a]["properties"]["displayName"]).split()[0][0]== "T"):
        Sentinel_Alerts.append((str(response3["value"][a]["properties"]["displayName"]).split()[0]))

print("[+] Techniques were extracted from your Azure Sentinel Analytics Successfully")

Total_Techniques = Sentinel_Detections + SentinelHunt_Queries + Local_Queries + Github_detect + Github_hunt

# Generate MITRE Layer

Layer_Template = {
    "description": "Techniques Covered by Azure Sentinel Rules and Queries",
    "name": "Azure Sentinel Coverage",
    "domain": "mitre-enterprise",
    "version": "4.1",
    "techniques": 
		[{  "techniqueID": technique, "color": "#ff0000"  } for technique in Total_Techniques] 
    ,
    "gradient": {
        "colors": [
            "#ffffff",
            "#ff0000"
        ],
        "minValue": 0,
        "maxValue": 1
    },
    "legendItems": [
        {
            "label": "Techniques Covered by Azure Sentinel",
            "color": "#ff0000"
        }
    ]
}

json_data = json.dumps(Layer_Template)

with open("MITRE_Matrix.json", "w") as file:
    json.dump(Layer_Template, file)

print("[+] The MITRE matrix json file 'MITRE_Matrix.json' was created successfully")
