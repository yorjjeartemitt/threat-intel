#ifndef DB_H
#define DB_H
void db_init();
void db_save(const char *ip,int scores, const char *country,const char *isp);
void db_save_setting(const char *key,const char *value);
char *db_get_setting(const char *key);
#endif