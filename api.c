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
char *check_ip(const char *ip){
	char header[128];
	struct curl_slist *headers = NULL;
	snprintf(header,sizeof(header),"Key: %s",getenv("API_KEY"));
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
		snprintf(res,256,"Score: %d | Country: %s | ISP: %s",score->valueint,country->valuestring,isp->valuestring);
		db_save(ip,score->valueint,country->valuestring,isp->valuestring);
		curl_easy_cleanup(curl);
		cJSON_Delete(json);
		curl_slist_free_all(headers);
		free(chunk.data);
		return res;

	}
	return NULL;
}
