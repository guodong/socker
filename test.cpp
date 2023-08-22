#include <map>
#include <iostream>

std::map<int, int> m;
class LoadBalancer {
  public:
    std::map<uint16_t, uint16_t> m;
};

LoadBalancer *lb = new LoadBalancer();
int main() {
  m[1] = 2;
  lb->m[2] = 3;
  std::cout << m.find(1)->second;
  return 0;
}