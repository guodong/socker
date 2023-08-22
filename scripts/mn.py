from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node
from mininet.link import TCLink
from mininet.log import setLogLevel, info
from mininet.cli import CLI


class Router(Node):
    def config(self, **params):
        super(Router, self).config(**params)
        # Enable forwarding on the router
        self.cmd('sysctl net.ipv4.ip_forward=1')

    def terminate(self):
        self.cmd('sysctl net.ipv4.ip_forward=0')
        super(Router, self).terminate()

b = 50

class MyTopo(Topo):
    def build( self, *args, **params ):
        h1 = self.addHost('h1', mac='00:00:00:00:00:01')
        h2 = self.addHost('h2', mac='00:00:00:00:00:02')
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        
        self.addLink(h1, s1) # the tc here prevent kprobe
        self.addLink(s1, s2, cls=TCLink, bw=50)
        self.addLink(s1, s3, cls=TCLink, bw=b)
        self.addLink(s2, s3, cls=TCLink, bw=b)
        self.addLink(s2, h2, cls=TCLink, bw=b)
        # self.addLink(s1, s2)
        # self.addLink(s1, s3)
        # self.addLink(s2, s3)
        # self.addLink(s2, h2)

topo = MyTopo()
net = Mininet(topo=topo,controller=None)
net.get('h1').cmd('arp -s 10.0.0.2 00:00:00:00:00:02')
net.get('h1').cmd('mount bpffs /sys/fs/bpf -t bpf')
net.get('h2').cmd('arp -s 10.0.0.1 00:00:00:00:00:01')
net.start()
CLI(net)
net.stop()
