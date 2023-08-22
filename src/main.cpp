#include <netinet/in.h>
#include <dlfcn.h>
#include <stdio.h>
#include <sys/queue.h>
#include <map>

#define MAX_UPSTREAM 4

class LoadBalancer {
  public:
    std::map<uint16_t, uint16_t> m;
};

__attribute__((init_priority(101))) LoadBalancer lb;


// int (*o_connect)(int, __CONST_SOCKADDR_ARG, socklen_t);
// void *o_connect;

int connect(int __fd, const struct sockaddr* __addr, socklen_t __len) {
  printf("socky\n");
  struct sockaddr_in *inaddr = (struct sockaddr_in *)__addr;
  short ori_port = ntohs(inaddr->sin_port);
  if (lb.m.find(ori_port) != lb.m.end()) {
    inaddr->sin_port = htons(lb.m.find(ntohs(inaddr->sin_port))->second);
  }
  auto o_connect = reinterpret_cast<int (*)(int, __CONST_SOCKADDR_ARG, socklen_t)>(dlsym(RTLD_NEXT, "connect"));
  // o_connect = dlsym(RTLD_NEXT, "connect");
  return o_connect(__fd, (struct sockaddr*)inaddr, __len);
}

__attribute__((constructor)) void __on_load(void) {
    printf("socky library loaded!\n");
  // addr_map[99] = 22;
  lb.m[99] = 22;
  // addr_map.insert(std::pair<short, short>(99, 22));
    printf("socky library loaded!\n");
}