#ifndef THREADPOOL_H
#define THREADPOOL_H
#include <pthread.h>
#define POOL_SIZE 4
#define QUEUE_MAX 32
typedef struct{
	void *(*fn)(void *);
	void *arg;
} Task;
typedef struct{
	Task queue[QUEUE_MAX];
	int head,tail,count;
	pthread_t workers[POOL_SIZE];
	pthread_mutex_t lock;
	pthread_cond_t has_task;
	int stop;
} ThreadPool;
void pool_init(ThreadPool *p);
void pool_submit(ThreadPool *p,void *(*fn)(void *),void *arg);
void pool_destroy(ThreadPool *p);
#endif
