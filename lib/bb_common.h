#ifndef BB_COMMON_H
#define BB_COMMON_H

#define BUFSIZE 4096
#define SERVER 0
#define CLIENT 1
#define DISCONNECTED 1
#define CONNECTED 2

#define SNAPSHOT_SIZE (1024*1024*5)
#define VIDEO_FRAME_SIZE (1024*1024*5)

#ifndef container_of 

#define container_of(ptr, type, member) ({           \
    const typeof(((type *)0)->member) *__ptr = (ptr);   \
    (type *)((char*)(ptr) - (intptr_t)(&((type *)0)->member)); })

//no type checking container
#define container_of_ntc(ptr, type, member) ({ \
    (type*)((char*)ptr - offsetof(type,member));})

#endif

#endif
