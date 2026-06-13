#ifndef DB_H
#define DB_H
void db_init();
void db_save(const char *ip,int scores, const char *country,const char *isp);
void db_save_setting(const char *key,const char *value);
char *db_get_setting(const char *key);
void db_cache_save(const char *ip, const char *checker,const char *result);
char *db_cache_get(const char *ip,const char *checker);
int db_get_checker_state(const char *name);
void db_save_checker_state(const char *name,int enabled);
#endif