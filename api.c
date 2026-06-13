#include <stdio.h>
#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <cjson/cJSON.h>
#include "api.h"
#include "db.h"
struct Memory {
	char *data;
	size_t size;
};

static size_t write_callback(void *content,size_t size,size_t nmemb,void *userp){
	size_t real_size=size*nmemb;
	struct Memory *mem=(struct Memory *)userp;
	mem->data=realloc(mem->data,mem->size+real_size+1);
	memcpy(&(mem->data[mem->size]),content,real_size);
	mem->size+=real_size;
	mem->data[mem->size]=0;
	return real_size;
}
char *check_abuseIPDB(const char *ip){
	char header[128];
	struct curl_slist *headers = NULL;
	snprintf(header,sizeof(header),"Key: %s",getenv("ABUSEIPDB"));
	headers = curl_slist_append(headers,header);
	CURL *curl=curl_easy_init();
	if (curl){
		struct Memory chunk={0};
		curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION,write_callback);
		curl_easy_setopt(curl,CURLOPT_WRITEDATA,&chunk);
		char url[256];
		snprintf(url,sizeof(url),"https://api.abuseipdb.com/api/v2/check?ipAddress=%s",ip);
		curl_easy_setopt(curl,CURLOPT_URL,url);
		curl_easy_setopt(curl,CURLOPT_HTTPGET,1L);
		curl_easy_setopt(curl,CURLOPT_HTTPHEADER,headers);
		curl_easy_perform(curl);
		if (!chunk.data){ 
			
			curl_slist_free_all(headers);
		    curl_easy_cleanup(curl);
		    return NULL;
		}
		cJSON *json = cJSON_Parse(chunk.data);
		if (json==NULL){
			free(chunk.data);
			return NULL;
		}
		cJSON *data = cJSON_GetObjectItem(json, "data");
		cJSON *score = cJSON_GetObjectItem(data, "abuseConfidenceScore");
		cJSON *country = cJSON_GetObjectItem(data, "countryCode");
		cJSON *isp = cJSON_GetObjectItem(data, "isp");
		if(!data || !score || !country || !isp){
		    cJSON_Delete(json);
		    curl_slist_free_all(headers);
		    free(chunk.data);
		    curl_easy_cleanup(curl); 
 		    return NULL;
		}
		char *res=malloc(256);
		snprintf(res,256,"Country: %s | Score: %d | %s",country->valuestring,score->valueint,isp->valuestring);
		db_save(ip,score->valueint,country->valuestring,isp->valuestring);
		curl_easy_cleanup(curl);
		cJSON_Delete(json);
		curl_slist_free_all(headers);
		free(chunk.data);
		return res;

	}
	return NULL;
}
char *check_virustotal(const char *ip){
	struct curl_slist *headers=NULL;
	char header[128];
	snprintf(header,sizeof(header),"x-apikey:%s",getenv("VIRUSTOTAL_API"));
	headers=curl_slist_append(headers,header);
	CURL *curl=curl_easy_init();
	if (curl){
		struct Memory chunk={0};
		char url[256];
		snprintf(url,sizeof(url),"https://www.virustotal.com/api/v3/ip_addresses/%s",ip);
		curl_easy_setopt(curl,CURLOPT_URL,url);
		curl_easy_setopt(curl,CURLOPT_HTTPHEADER,headers);
		curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION,write_callback);
		curl_easy_setopt(curl,CURLOPT_WRITEDATA,&chunk);
		curl_easy_perform(curl);
		curl_easy_cleanup(curl);
		curl_slist_free_all(headers);
		if (!chunk.data){
			return NULL;
		}
		cJSON *json=cJSON_Parse(chunk.data);
		free(chunk.data);
		if (!json){
			return NULL;
		}
		cJSON *data=cJSON_GetObjectItem(json,"data");
		cJSON *attrs=cJSON_GetObjectItem(data,"attributes");
		cJSON *stats=cJSON_GetObjectItem(attrs,"last_analysis_stats");
		cJSON *mal=cJSON_GetObjectItem(stats,"malicious");
		char *res=malloc(64);
		snprintf(res,64,"%d Malicious",mal ? mal->valueint:-1);
		cJSON_Delete(json);
		return res;
	}
	return NULL;
}
char *check_shodan(const char *ip){
	CURL *curl=curl_easy_init();
	if (curl){
		struct Memory chunk={0};
		char url[256];
		snprintf(url,sizeof(url),"https://api.shodan.io/shodan/host/%s?key=%s",ip,getenv("SHODAN_API"));
		curl_easy_setopt(curl,CURLOPT_URL,url);
		curl_easy_setopt(curl,CURLOPT_HTTPGET,1L);
		curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION,write_callback);
		curl_easy_setopt(curl,CURLOPT_WRITEDATA,&chunk);
		curl_easy_perform(curl);
		curl_easy_cleanup(curl);
		if (!chunk.data) return NULL;
		cJSON *json=cJSON_Parse(chunk.data);
		free(chunk.data);
		if (!json) return NULL;
		cJSON *org=cJSON_GetObjectItem(json,"org");
		cJSON *country=cJSON_GetObjectItem(json,"country_name");
		cJSON *port=cJSON_GetObjectItem(json,"ports");
		if (!org||!country||!port){
			cJSON_Delete(json);
			return NULL;
		}
		char port_str[256]={0};
		int count=cJSON_GetArraySize(port);
		for (int i=0;i<count && i<8;i++){
			cJSON *p=cJSON_GetArrayItem(port,i);
			char tmp[16];
			snprintf(tmp,sizeof(tmp),i==0? "%d":",%d",p->valueint);
			strncat(port_str,tmp,sizeof(port_str)-strlen(port_str)-1);
		}
		char *res=malloc(512);
		snprintf(res,512,"Country: %s | port: %s | %s",country->valuestring,port_str,org->valuestring);
		cJSON_Delete(json);
		return res;

	}
	return NULL;
}
char *check_ipinfo(const char *ip){
	char header[128];
	struct curl_slist *headers=NULL;
	snprintf(header,sizeof(header),"Authorization: Bearer %s",getenv("IPINFO"));
	headers=curl_slist_append(headers,header);
	CURL *curl=curl_easy_init();
	if (curl){
		struct Memory chunk={0};
		char url[256];
		snprintf(url,sizeof(url),"https://ipinfo.io/%s/json",ip);
		curl_easy_setopt(curl,CURLOPT_URL,url);
		curl_easy_setopt(curl,CURLOPT_HTTPGET,1L);
		curl_easy_setopt(curl,CURLOPT_HTTPHEADER,headers);
		curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION,write_callback);
		curl_easy_setopt(curl,CURLOPT_WRITEDATA,&chunk);
		curl_easy_perform(curl);
		curl_easy_cleanup(curl);
		curl_slist_free_all(headers);
		if (!chunk.data) return NULL;
		cJSON *json=cJSON_Parse(chunk.data);
		free(chunk.data);
		if (!json) return NULL;
		cJSON *city=cJSON_GetObjectItem(json,"city");
		cJSON *country=cJSON_GetObjectItem(json,"country");
		cJSON *org=cJSON_GetObjectItem(json,"org");
		cJSON *timezone=cJSON_GetObjectItem(json,"timezone");
		if (!city||!country||!org||!timezone){
			cJSON_Delete(json);
			return NULL;
		}
		char *res=malloc(256);
		snprintf(res,256,"Country: %s | City: %s, %s | %s",country->valuestring,city->valuestring,timezone->valuestring,org->valuestring);
		cJSON_Delete(json);
		return res;
	}
	return NULL;
}
char *check_pulsedive(const char *ip){
	CURL *curl=curl_easy_init();
	if (curl){
		struct Memory chunk={0};
		char url[256];
		snprintf(url,sizeof(url),"https://pulsedive.com/api/info.php?indicator=%s&pretty=1&key=%s",ip,getenv("PULSE_DIVE"));
		curl_easy_setopt(curl,CURLOPT_URL,url);
		curl_easy_setopt(curl,CURLOPT_HTTPGET,1L);
		curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION,write_callback);
		curl_easy_setopt(curl,CURLOPT_WRITEDATA,&chunk);
		curl_easy_perform(curl);
		curl_easy_cleanup(curl);
		if (!chunk.data) return NULL;
		cJSON *json=cJSON_Parse(chunk.data);
		free(chunk.data);
		if (!json) return NULL;
		cJSON *risk=cJSON_GetObjectItem(json,"risk");
		cJSON *stamp_seen=cJSON_GetObjectItem(json,"stamp_seen");
		cJSON *threats=cJSON_GetObjectItem(json,"threats");

		if (!risk){
			cJSON_Delete(json);
			return NULL;
		}
		int threat_count=threats ? cJSON_GetArraySize(threats):0;	
		char *res=malloc(256);
		snprintf(res,256,"Risk: %s | Last view: %s | Threats: %d",risk->valuestring,stamp_seen?stamp_seen->valuestring:"unknown",threat_count);
		cJSON_Delete(json);
		return res;
	}
	return NULL;
}
char *check_alien_vault_otx(const char *ip){
	CURL *curl=curl_easy_init();
	if (curl){
		struct Memory chunk={0};
		char url[256];
		char header[128];
		struct curl_slist *headers=NULL;
		snprintf(header,sizeof(header),"X-OTX-API-KEY: %s",getenv("ALIEN_VAULT_OTX"));
		headers=curl_slist_append(headers,header);
		snprintf(url,sizeof(url),"https://otx.alienvault.com/api/v1/indicators/IPv4/%s/general",ip);
		curl_easy_setopt(curl,CURLOPT_URL,url);
		curl_easy_setopt(curl,CURLOPT_HTTPHEADER,headers);
		curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION,write_callback);
		curl_easy_setopt(curl,CURLOPT_WRITEDATA,&chunk);
		curl_easy_perform(curl);
		curl_easy_cleanup(curl);
		curl_slist_free_all(headers);
		if (!chunk.data) return NULL;
		cJSON *json=cJSON_Parse(chunk.data);
		free(chunk.data);
		if (!json) return NULL;
		cJSON *pulse_info=cJSON_GetObjectItem(json,"pulse_info");
		cJSON *count=cJSON_GetObjectItem(pulse_info,"count");
		cJSON *country=cJSON_GetObjectItem(json,"country_code");

		if (!pulse_info||!count){
			cJSON_Delete(json);
			return NULL;
		}
		char *res=malloc(128);
		snprintf(res,128,"Country: %s | Pulses: %d",country?country->valuestring:"unknown",count->valueint);
		cJSON_Delete(json);
		return res;
	}
	return NULL;
}
char *check_ipqs(const char *ip){
	CURL *curl=curl_easy_init();
	if (curl){
		struct Memory chunk={0};
		char url[256];
		snprintf(url,sizeof(url),"https://ipqualityscore.com/api/json/ip/%s/%s",getenv("IPQS"),ip);
		curl_easy_setopt(curl,CURLOPT_URL,url);
		curl_easy_setopt(curl,CURLOPT_HTTPGET,1L);
		curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION,write_callback);
		curl_easy_setopt(curl,CURLOPT_WRITEDATA,&chunk);
		curl_easy_perform(curl);
		curl_easy_cleanup(curl);
		if (!chunk.data) return NULL;
		cJSON *json=cJSON_Parse(chunk.data);
		free(chunk.data);
		if (!json) return NULL;
		cJSON *fraud=cJSON_GetObjectItem(json,"fraud_score");
		cJSON *proxy=cJSON_GetObjectItem(json,"proxy");
		cJSON *vpn=cJSON_GetObjectItem(json,"vpn");
		cJSON *tor=cJSON_GetObjectItem(json,"tor");
		cJSON *country=cJSON_GetObjectItem(json,"country_code");
		if (!fraud){
			cJSON_Delete(json);
			return NULL;
		}
		char *res=malloc(128);
		snprintf(res,128,"Country: %s | Fraud: %d | Proxy: %s | VPN: %s | Tor: %s",country?country->valuestring:"unknown",fraud->valueint,proxy && proxy->type==cJSON_True ? "yes":"no",vpn && vpn->type==cJSON_True ? "yes":"no", tor && tor->type==cJSON_True ? "yes":"no");		
		cJSON_Delete(json);
		return res;
	}
	return NULL;
}