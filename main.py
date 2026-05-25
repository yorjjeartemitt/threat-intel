import requests
from dotenv import load_dotenv
import os
from db import init_db,save_reports
ip_n=["8.8.8.8","8.8.4.4","1.1.1.1","192.102.101.1"]

def ips():
	url=["https://feodotracker.abuse.ch/downloads/ipblocklist.txt","https://cinsscore.com/list/ci-badguys.txt","https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"]
	for i in url:

		response=requests.get(i)
		for x in response.text.splitlines():
			if x and x[0]!="#":
				ip_n.append(x.split()[0])
ips()
load_dotenv()
API_KEY = os.getenv("API_KEY")
def check_ip(ip):
	url="https://api.abuseipdb.com/api/v2/check"
	headers={"Key": API_KEY, "Accept":"application/json"}
	params={"ipAddress":ip,"maxAgeInDays": 90}
	response=requests.get(url,headers=headers,params=params)
	return response.json()
if __name__=="__main__":
	init_db()
	for i in ip_n:
		res=check_ip(i)
		datas=res["data"]
		ip=datas["ipAddress"]
		score=datas["abuseConfidenceScore"]
		country=datas["countryCode"]
		save_reports(ip,score,country)
		print(f"{ip}| score: {score} | country: {country}")