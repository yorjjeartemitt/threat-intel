#include "threadpool.h"
#include <stdlib.h>
static void *worker(void *arg){
    ThreadPool *p=(ThreadPool *)arg;
    while (1){
        pthread_mutex_lock(&p->lock);
        while (p->count==0 && !p->stop){
            pthread_cond_wait(&p->has_task,&p->lock);
        }
        if (p->stop && p->count==0){
            pthread_mutex_unlock(&p->lock);
            return NULL;
        }
        Task t=p->queue[p->head];
        p->head=(p->head+1)%QUEUE_MAX;
        p->count--;
        pthread_mutex_unlock(&p->lock);
        t.fn(t.arg);
    }
}
void pool_init(ThreadPool *p){
    p->head=p->tail=p->count=p->stop=0;
    pthread_mutex_init(&p->lock,NULL);
    pthread_cond_init(&p->has_task,NULL);
    for (int i=0;i<POOL_SIZE;i++){
        pthread_create(&p->workers[i],NULL,worker,p);
    }
}
void pool_submit(ThreadPool *p,void *(*fn)(void *),void *arg){
    pthread_mutex_lock(&p->lock);
    if (p->count<QUEUE_MAX){
        p->queue[p->tail].fn=fn;
        p->queue[p->tail].arg=arg;
        p->tail=(p->tail+1)%QUEUE_MAX;
        p->count++;
        pthread_cond_signal(&p->has_task);
    }
    pthread_mutex_unlock(&p->lock);
}
void pool_destroy(ThreadPool *p){
    pthread_mutex_lock(&p->lock);
    p->stop=1;
    pthread_cond_broadcast(&p->has_task);
    pthread_mutex_unlock(&p->lock);
    for (int i=0;i<POOL_SIZE;i++){
        pthread_join(p->workers[i],NULL);
    }
    pthread_mutex_destroy(&p->lock);
    pthread_cond_destroy(&p->has_task);
}