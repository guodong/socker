#include <netinet/in.h>
#include <dlfcn.h>
#include <stdio.h>
#include <sys/queue.h>

#define MAX_UPSTREAM 4


struct upstream {
  int pod_ip;
  LIST_ENTRY(upstream) upstreams;
};

LIST_HEAD(upstream_list, upstream) head;


typedef struct lb_info {
  int cluster_ip;
  int pod_ip[MAX_UPSTREAM];
  struct upstream_list *list;
} lb_info_t;


int (*o_connect)(int, __CONST_SOCKADDR_ARG, socklen_t);


int connect(int __fd, const struct sockaddr* __addr, socklen_t __len) {
  printf("socky\n");
  o_connect = dlsym(RTLD_NEXT, "connect");
  return o_connect(__fd, (struct sockaddr*)__addr, __len);
}

__attribute__((constructor))  void __on_load(void) {
    printf("socky library loaded!\n");


}