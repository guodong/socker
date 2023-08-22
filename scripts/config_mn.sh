#!/bin/bash
sudo ovs-ofctl add-flow s1 dl_vlan=0x1,actions=strip_vlan,output:1
sudo ovs-ofctl add-flow s1 dl_vlan=0x2,actions=strip_vlan,output:2
sudo ovs-ofctl add-flow s1 dl_vlan=0x3,actions=strip_vlan,output:3
sudo ovs-ofctl add-flow s2 dl_vlan=0x1,actions=strip_vlan,output:1
sudo ovs-ofctl add-flow s2 dl_vlan=0x2,actions=strip_vlan,output:2
sudo ovs-ofctl add-flow s2 dl_vlan=0x3,actions=strip_vlan,output:3
sudo ovs-ofctl add-flow s3 dl_vlan=0x1,actions=strip_vlan,output:1
sudo ovs-ofctl add-flow s3 dl_vlan=0x2,actions=strip_vlan,output:2

# response path
sudo ovs-ofctl add-flow s2 in_port=3,actions=output:1
sudo ovs-ofctl add-flow s1 in_port=2,actions=output:1


# sudo ovs-ofctl add-flow s1 ip,nw_dst=10.0.0.2,actions=output:2
# sudo ovs-ofctl add-flow s2 ip,nw_dst=10.0.0.2,actions=output:3

# for high bw flow
sudo ovs-ofctl add-flow s1 priority=40000,tcp,tcp_dst=8080,actions=output:3
sudo ovs-ofctl add-flow s3 priority=40000,tcp,tcp_dst=8080,actions=output:2
sudo ovs-ofctl add-flow s2 priority=40000,tcp,tcp_dst=8080,actions=output:3