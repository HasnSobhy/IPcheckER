import base64
import datetime
from jinja2 import Environment, FileSystemLoader
from json2html import json2html
import requests
import json
from prettytable import PrettyTable
from colorama import Fore, Back, Style
import re
from tqdm import tqdm
import time
import os




# Define a list of IP addresses to check
myfile= open("ips.txt", "r")
data=myfile.read()
ips = data.split("\n")
myfile.close()

VTreport="D:/VT.html"
IBMreport="D:/IBM.html"

table = PrettyTable()

def get_variable_values(variables):
    
    try:
        # Try to open the file in read mode
        with open("apis.json", "r") as file:
            variable_values = json.load(file)
    except FileNotFoundError:
        # If the file doesn't exist, prompt the user for the values
        variable_values = {}
        for variable in variables:
            value = input(f"Enter the value for '{variable}': ")
            variable_values[variable] = value

        # Save the values to the file
        with open("apis.json", "w") as file:
            json.dump(variable_values, file)
    
    return variable_values


def cmdTable(x,m,f,y,z,h,l):
 
    # add columns to the table
    table.field_names = [ "IP","country" ,"VirusTotal", "Owner", "AbuseIPDB", "AlienVault","issuer" ]

    # add rows to the table
    table.add_row([x,m,f,y,z,h,l])
    table.add_row(["","","", "", "", "",""])
    table.header_style = 'upper'


    # print the table to the terminal
    return table


def getResponse(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response
    else:
        return None

#Get VirusTotal reputation    

def getVTreputation(ip):
    VTresponse=getResponse(ip)
    TXTresponse=VTresponse.text        
    #vt_report = get_vt_report(response) 
    if TXTresponse:    
        VTjson=VTresponse.json()
        try:
            country = VTjson['data']['attributes']['country']
        except KeyError:
            country= None
        VTJsonResponse=json.loads(TXTresponse)
        community_score_info = printCommunityScore(VTJsonResponse)
    return community_score_info,country
     

def printCommunityScore(vtJR):
     # grab "malicious" key data from last_analysis_stats to create the first part of the community_score_info
        try:
            community_score = (vtJR["data"]["attributes"]["last_analysis_stats"]["malicious"])
        except KeyError:
            community_score= None
         # grab the sum of last_analysis_stats to create the total number of security vendors that reviewed the URL for the second half of the community_score_info
        total_vt_reviewers = (vtJR["data"]["attributes"]["last_analysis_stats"]["harmless"])+(vtJR["data"]["attributes"]["last_analysis_stats"]["malicious"])+(vtJR["data"]["attributes"]["last_analysis_stats"]["suspicious"])+(vtJR["data"]["attributes"]["last_analysis_stats"]["undetected"])+(vtJR["data"]["attributes"]["last_analysis_stats"]["timeout"])

         # create a custom community score using community_score and the total_vt_reviewers values
        community_score_info = str(community_score)+ ("/") + str(total_vt_reviewers) + (" malicious")
        return community_score_info


#Get the IBM X-Force report for an IP
def getIBMreputation(ip):
    url = f"https://api.xforce.ibmcloud.com/ipr/{ip}"
    headers = {"Authorization": IBM_API_KEY, "Accept": "application/json"}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        rate = str(response.json()['history'][-1]['score']) + " out of 10 Malicious"
        IBMjson=response.json()
       
        category=IBMjson['history'][len(IBMjson['history'])-1]['cats']
        return rate,category
    else:
        return None

# Define a function to get the AbuseIPDB report for an IP
def getABUSEreputation(ip):
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:

        ABUSEjsonresponse = response.json()
        if 'data' in ABUSEjsonresponse:
            community_scoreabuse = ABUSEjsonresponse['data']['abuseConfidenceScore']
            #print(f"The community score for IP address {ip} is {community_score}")
            return community_scoreabuse
        else:
            print('No data found for the IP address')
    else:
        return None

def GetAlienVaultCS(ipa,api):
    otx_url = f'https://otx.alienvault.com/api/v1/indicators/IPv4/{ipa}/general'
    otx_headers = {'X-OTX-API-KEY': OTX_API_KEY}
    otx_response = requests.get(otx_url, headers=otx_headers)
    if otx_response.status_code == 200:
        otx_response_json = json.loads(otx_response.content)

        if 'pulse_info' in otx_response_json:
                community_scoreOTX = otx_response_json['pulse_info']['count']
                return community_scoreOTX
                #print(f"The community score for IP address {ipa} is {community_score}")
        else:
                print('No community score found for the IP address')
    else:
            print(f'OTX request failed with status code {otx_response.status_code}')



#Functions for report generation
def deleteData(JsonResponse):
    del JsonResponse["data"]["attributes"]["last_analysis_results"]
    


def getInfo(ip):
    VTresponse=getResponse(ip)
    TXTresponse=VTresponse.text        
    #vt_report = get_vt_report(response) 
    if TXTresponse:    
        VTjson=VTresponse.json()
        deleteData(VTjson)
        try:
            country = VTjson['data']['attributes']['country']
        except KeyError:
            country = None

        try:
            lastdate = VTjson['data']['attributes']['last_analysis_date']
            lastAnalysisDate = datetime.datetime.fromtimestamp(lastdate)
        except KeyError:
            lastAnalysisDate = None

        try:
            network = VTjson['data']['attributes']['network']
        except KeyError:
            network = None

        try:
            owner = VTjson['data']['attributes']['as_owner']
        except KeyError:
            owner = None

        try:
            tags = VTjson['data']['attributes']['tags']
        except KeyError:
            tags = None

        try:
            lastAnalysisState = VTjson['data']['attributes']['last_analysis_stats']
        except KeyError:
            lastAnalysisState = None

        try:
            Validation = VTjson['data']['attributes']['last_https_certificate']['validity']
        except KeyError:
            Validation = None

        try:
            issuer = VTjson['data']['attributes']['last_https_certificate']['issuer']
        except KeyError:
            issuer = None

        try:
            subject = VTjson['data']['attributes']['last_https_certificate']['subject']
        except KeyError:
            subject = None
        VTJsonResponse=json.loads(TXTresponse)
        community_score_info = printCommunityScore(VTJsonResponse)
    return community_score_info,country,owner,lastAnalysisState,Validation,issuer,subject,tags,lastAnalysisDate,network


def getReferrerFiles(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/referrer_files"
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        
        data = json.loads(response.content)
   
        item_list = []

        counter=0
        for file in data['data']:
                fileName=file['attributes']['names']
                fileType=file['attributes']['type_description']
                fileSize=file['attributes']['size']
                fileHash=file['attributes']['sha256']
                DetectionRatio=file['attributes']['last_analysis_stats']['malicious']
                item_dict = {'filename': fileName, 'filetype':fileType, 'filesize':fileSize, 'filehash':fileHash, 'detectionratio':DetectionRatio}

                item_list.append(item_dict)

              
        return item_list
                
    else:
        print("error")




def get_commfiles(ipa):

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ipa}/communicating_files"
    headers = {"x-apikey": VT_API_KEY }
    response = requests.get(url, headers=headers)
   
    if response.status_code == 200:
        
        data = response.json()
        
        if "data" in data:
            comm_list = []
            relations = data["data"]
            
            for relation in relations:
                try:
                    name = relation["attributes"]["names"]
                    
                except KeyError:
                    name = None

                try:
                    type_description = relation["attributes"]["type_description"]
                except KeyError:
                    type_description = None

                try:
                    size = relation["attributes"]["size"]
                except KeyError:
                    size = None

                try:
                    md5 = relation["attributes"]["md5"]
                except KeyError:
                    md5 = None

                try:
                    Reputation = relation["attributes"]["last_analysis_stats"]["malicious"]
                    
                except KeyError:
                    reputation = None

                try:
                    magic = relation["attributes"]["magic"]
                except KeyError:
                    magic = None

                try:
                    packers = relation["attributes"]["packers"]
                except KeyError:
                    packers = None

                try:
                    type_tags = relation["attributes"]["type_tags"]
                except KeyError:
                    type_tags = None

                try:
                    sandbox_verdicts = relation["attributes"]["sandbox_verdicts"]
                except KeyError:
                    sandbox_verdicts = None

                comm_dict = {'name': name, 'type_description': type_description, 'size': size, "md5": md5,
                            'reputation': Reputation, 'magic': magic, 'packers': packers, 'type_tags': type_tags,
                            'sandbox_verdicts': sandbox_verdicts}
                
                comm_list.append(comm_dict)

        return comm_list

# comments for ip

def get_ip_comments(api_key, ip_address):
    base_url = "https://www.virustotal.com/api/v3/ip_addresses"
    headers = {"x-apikey": api_key}

    # Make request to get comments for the IP address
    response = requests.get(f"{base_url}/{ip_address}/comments", headers=headers)

    if response.status_code == 200:
        data = response.json().get("data", [])
        return data
    else:
        print(f"Error: {response.status_code} - {response.text}")
        return []

def create_html_table(comments):
    table_html = "<table class='comments-table'>\n"
    table_html += "<tr><th>Comment</th><th>Additional Info</th></tr>\n"

    for comment_info in comments:
        comment = comment_info.get("attributes", {}).get("text", "No comment")
        additional_info = str(comment_info.get("attributes", {}).get("votes", 0))
        table_html += f"<tr><td>{comment}</td><td>{additional_info}</td></tr>\n"

    table_html += "</table>"
    return table_html





def renderHtml(ipreport):
    
    template_path = 'template.html'
    env = Environment(loader=FileSystemLoader('.'))
    template = env.get_template(template_path)

    #add refferer files 
    reputation,country,asowner,lastanalysis,validate,issuer,subject,tags,lastAnalysisDate,network=getInfo(ipreport) 
    referrerList=getReferrerFiles(ipreport)
   
    commfiles=get_commfiles(ipreport)

    #add comments for ip
    table_html=""
    comments = get_ip_comments(VT_API_KEY, ipreport)
    if comments:
        
        table_html = create_html_table(comments)
       
    
    
    
    html = template.render(
    ip_address=ipreport,
    reputation=reputation,
    country=country,
    owner=asowner,
    last_analysis_stats=lastanalysis,
    validity=validate,
    issuer=issuer,
    subject=subject,
    tags=tags,
    last_analysis_date=lastAnalysisDate,
    network=network,
    item_list=referrerList,comm_list=commfiles,table_html=table_html)


    folder_path = "report/"
    os.makedirs(folder_path, exist_ok=True)
    file_name = "report_"+ ipreport +".html"
    file_path = os.path.join(folder_path, file_name)
    with open(file_path, 'w') as f:
        f.write(html)


# fucntion to know public IP
def is_private_ip(ip_address):
    ip_parts = ip_address.split('.')
    
    if len(ip_parts) != 4:
        print("Invalid IP")
        return False
    
    for part in ip_parts:
        if not part.isdigit() or not (0 <= int(part) <= 255):
            print("Invalid IP")
            return False
    
    first_octet = int(ip_parts[0])
    second_octet = int(ip_parts[1])
    
    if (first_octet == 10) or (first_octet == 172 and 16 <= second_octet <= 31) or (first_octet == 192 and second_octet == 168):
        return False
    else:
        return True



# Define API keys for each service

variables = ['VirusTotal_API_KEY', 'ABUSEIPDB_API_KEY', 'OTX_API_KEY']

# Get variable values from the user or file
values = get_variable_values(variables)

# Access and use the stored values later in your code
VT_API_KEY = values['VirusTotal_API_KEY']
ABUSEIPDB_API_KEY = values['ABUSEIPDB_API_KEY']
OTX_API_KEY = values['OTX_API_KEY']

ip_address_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')




# Loop through the list of IPs and get reports for each one
size=len(ips)

for ip in tqdm(ips, desc="Processing", unit="IP" ):
    
    if ip_address_pattern.match(ip):

        if (is_private_ip(ip)):
            VTreputation,VTcountry=getVTreputation(ip)
            #IBMreputation,IBMcategory=getIBMreputation(ip)
        
            ABUSErepuation=getABUSEreputation(ip)
            communityscoreAV=GetAlienVaultCS(ip,OTX_API_KEY)
            reputation,country,asowner,lastanalysis,validate,issuer,subject,tags,lastAnalysisDate,network=getInfo(ip)
            
            finalTable= cmdTable(ip,VTcountry,VTreputation,asowner,ABUSErepuation,communityscoreAV,issuer)
    time.sleep(0.5)
tqdm()
#print(Fore.GREEN + Back.BLACK + Style.DIM )



print(finalTable)


while True:
    ipreport=input("Enter ip to generate report or E to END: ")
    if ipreport == "E" or ipreport == "e": 
        break

    elif (is_private_ip(ipreport)):
        renderHtml(ipreport)
        print(Fore.GREEN + "report done for " + ipreport +"..")
        print(Style.RESET_ALL)
        

             
#######################################################
