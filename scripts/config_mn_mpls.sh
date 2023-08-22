#!/bin/bash
sudo ovs-ofctl add-flow s1 dl_type=0x8847,mpls_label=0x1,actions=pop_mpls:0x0800,output:1
sudo ovs-ofctl add-flow s1 dl_type=0x8847,mpls_label=0x2,actions=pop_mpls:0x0800,output:2
sudo ovs-ofctl add-flow s1 dl_type=0x8847,mpls_label=0x3,actions=pop_mpls:0x0800,output:3
sudo ovs-ofctl add-flow s2 dl_type=0x8847,mpls_label=0x1,actions=pop_mpls:0x0800,output:1
sudo ovs-ofctl add-flow s2 dl_type=0x8847,mpls_label=0x2,actions=pop_mpls:0x0800,output:2
sudo ovs-ofctl add-flow s2 dl_type=0x8847,mpls_label=0x3,actions=pop_mpls:0x0800,output:3
sudo ovs-ofctl add-flow s3 dl_type=0x8847,mpls_label=0x1,actions=pop_mpls:0x0800,output:1
sudo ovs-ofctl add-flow s3 dl_type=0x8847,mpls_label=0x2,actions=pop_mpls:0x0800,output:2