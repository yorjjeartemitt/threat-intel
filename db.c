#include <sqlite3.h>
#include <stdio.h>
#include "db.h"
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