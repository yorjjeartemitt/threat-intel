#include <sqlite3.h>
#include <stdio.h>
#include "db.h"
#include <string.h>
void db_init(){
	sqlite3 *db;
	int rc=sqlite3_open("threats.db",&db);
	if (rc!=SQLITE_OK){
		fprintf(stderr,"db open error:%s\n",sqlite3_errmsg(db));
		return;
	}
	rc=sqlite3_exec(db,"CREATE TABLE IF NOT EXISTS reports("
		"id INTEGER PRIMARY KEY AUTOINCREMENT,"
		"ip TEXT,score INTEGER,country TEXT,isp TEXT,"
		"checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);",NULL,NULL,NULL);
	if (rc!=SQLITE_OK){
		fprintf(stderr,"db create error:%s\n",sqlite3_errmsg(db));
	}
	sqlite3_exec(db,
    "CREATE TABLE IF NOT EXISTS cache("
    "ip TEXT NOT NULL,"
    "checker TEXT NOT NULL,"
    "result TEXT,"
    "checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
    "PRIMARY KEY(ip,checker));",
    NULL,NULL,NULL);
    sqlite3_exec(db,"CREATE TABLE IF NOT EXISTS checker_state(" "name TEXT PRIMARY KEY, enabled INTEGER);",NULL,NULL,NULL);
	sqlite3_close(db);
}
void db_save(const char *ip, int score,const char *country,const char *isp){
	sqlite3 *db;
	sqlite3_open("threats.db",&db);
	sqlite3_stmt *stmt;
	sqlite3_prepare_v2(db,"INSERT INTO reports (ip,score,country,isp) VALUES (?,?,?,?);",-1,&stmt,NULL);
	sqlite3_bind_text(stmt,1,ip,-1, SQLITE_STATIC);
	sqlite3_bind_int(stmt,2,score);
	sqlite3_bind_text(stmt,3,country,-1,SQLITE_STATIC);
	sqlite3_bind_text(stmt,4,isp,-1,SQLITE_STATIC);
	sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	sqlite3_close(db);
}
void db_save_setting(const char *key,const char *value){
	sqlite3 *db;
	sqlite3_open("threats.db",&db);
	sqlite3_exec(db,"CREATE TABLE IF NOT EXISTS settings("
		"key TEXT PRIMARY KEY, value TEXT);",NULL,NULL,NULL);
	sqlite3_stmt *stmt;
	sqlite3_prepare_v2(db,"INSERT OR REPLACE INTO settings (key,value) VALUES (?,?);",-1,&stmt,NULL);
	sqlite3_bind_text(stmt,1,key,-1,SQLITE_STATIC);
	sqlite3_bind_text(stmt,2,value,-1,SQLITE_STATIC);
	sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	sqlite3_close(db);
}
char *db_get_setting(const char *key){
	sqlite3 *db;
	sqlite3_open("threats.db",&db);
	sqlite3_stmt *stmt;
	sqlite3_prepare_v2(db,"SELECT value FROM settings WHERE key=?;",-1,&stmt,NULL);
	sqlite3_bind_text(stmt,1,key,-1,SQLITE_STATIC);
	char *result=NULL;
	if (sqlite3_step(stmt)==SQLITE_ROW){
		result=strdup((const char *)sqlite3_column_text(stmt,0));
	}
	sqlite3_finalize(stmt);
	sqlite3_close(db);
	return result;
}
void db_cache_save(const char *ip, const char *checker, const char *result){
    sqlite3 *db;
    sqlite3_open("threats.db",&db);
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO cache(ip,checker,result) VALUES(?,?,?);"
        ,-1,&stmt,NULL);
    sqlite3_bind_text(stmt,1,ip,-1,SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt,2,checker,-1,SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt,3,result,-1,SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    sqlite3_close(db);
}

char *db_cache_get(const char *ip, const char *checker){
	sqlite3 *db;
	sqlite3_open("threats.db",&db);
	sqlite3_stmt *stmt;
	sqlite3_prepare_v2(db,"SELECT result FROM cache WHERE ip=? AND checker=?;",-1,&stmt,NULL);
	sqlite3_bind_text(stmt,1,ip,-1,SQLITE_STATIC);
	sqlite3_bind_text(stmt,2,checker,-1,SQLITE_STATIC);
	char *result=NULL;
	if (sqlite3_step(stmt)==SQLITE_ROW){	
		const char *col=(const char *)sqlite3_column_text(stmt,0);
		if (col) result=strdup(col);

	}
	sqlite3_finalize(stmt);
	sqlite3_close(db);
	return result;
}
void db_save_checker_state(const char *name,int enabled){
	sqlite3 *db;
	sqlite3_open("threats.db",&db);
	sqlite3_stmt *stmt;
	sqlite3_prepare_v2(db,"INSERT OR REPLACE INTO checker_state(name,enabled) VALUES(?,?);",-1,&stmt,NULL);
	sqlite3_bind_text(stmt,1,name,-1,SQLITE_TRANSIENT);
	sqlite3_bind_int(stmt,2,enabled);
	sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	sqlite3_close(db);
}
int db_get_checker_state(const char *name){
	sqlite3 *db;
	sqlite3_open("threats.db",&db);
	sqlite3_stmt *stmt;
	sqlite3_prepare_v2(db,"SELECT enabled FROM checker_state WHERE name=?;",-1,&stmt,NULL);
	sqlite3_bind_text(stmt,1,name,-1,SQLITE_TRANSIENT);
	int result=1;
	if (sqlite3_step(stmt)==SQLITE_ROW){
		result=sqlite3_column_int(stmt,0);
	}
	sqlite3_finalize(stmt);
	sqlite3_close(db);
	return result;
}
