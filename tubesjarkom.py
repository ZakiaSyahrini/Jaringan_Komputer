from mininet.net import Mininet
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.node import Node
from mininet.topo import Topo
from mininet.log import setLogLevel, info
from mininet.util import pmonitor
from signal import SIGINT
from time import time
import os

def testIperf( net, server='h0', clients=('h1') ):
    popens = {}
    tperf = 20
    tout = ( tperf + 1 ) * 4
    stopPerf = time() + tout + 5
    inv = 4

    popens[ net[ server ] ] = net[ server ].popen( 'iperf -s -t '+str( tout ) )
    for client in clients:
        client = 'h1'
        popens[ net[ client ] ] = net[ client ].popen( 'iperf -c '+net[ server ].IP()+' -i '+str(inv)+' -t '+str( tperf ) )
        break

    logserver = logclient1 = logclient2 = logclient3 = ""

    for host, line in pmonitor(popens, timeoutms=(tperf + tout) * 4):
        if host:
            if host.name == server: logserver += (host.name +": "+line)
            elif host.name == clients[0]: logclient1 += (host.name +": "+line)
            # elif host.name == clients[1]: logclient2 += (host.name +": "+line)
            # elif host.name == clients[2]: logclient3 += (host.name +": "+line)

        if time() >= stopPerf:
            for p in popens.values(): p.send_signal(SIGINT)

    print(logserver)
    print(logclient1)
    print(logclient2)
    print(logclient3)
    
def routerNet():
    # Run Mininet
    net = Mininet( link=TCLink )

#CLO1
  
    # Add Router
    r1 = net.addHost( 'r1', ip='192.168.0.2/24')
    r2 = net.addHost( 'r2', ip='192.168.5.1/24')
    r3 = net.addHost( 'r3', ip='192.168.2.1/24')
    r4 = net.addHost( 'r4', ip='192.168.6.2/24')
    
    # Add Host h0,h1
    h0 = net.addHost( 'h0', ip='192.168.0.1/24')
    h1 = net.addHost( 'h1', ip='192.168.2.2/24')
     
    # Add Link
    net.addLink(h0, r1, max_queue_size=100, intfName1='h0-eth0',intfName2='r1-eth0', cls=TCLink, bw=1 )
    net.addLink(h0, r2, max_queue_size=100, intfName1='h0-eth1',intfName2='r2-eth1', cls=TCLink, bw=1 )
    net.addLink(h1, r3, max_queue_size=100, intfName1='h1-eth0',intfName2='r3-eth0', cls=TCLink, bw=1 )
    net.addLink(h1, r4, max_queue_size=100, intfName1='h1-eth1',intfName2='r4-eth1', cls=TCLink, bw=1 )
    net.addLink(r1, r3, max_queue_size=100, intfName1='r1-eth1',intfName2='r3-eth1', cls=TCLink, bw=0.5 )
    net.addLink(r1, r4, max_queue_size=100, intfName1='r1-eth2',intfName2='r4-eth2', cls=TCLink, bw=1 )
    net.addLink(r2, r4, max_queue_size=100, intfName1='r2-eth0',intfName2='r4-eth0', cls=TCLink, bw=0.5 )
    net.addLink(r2, r3, max_queue_size=100, intfName1='r2-eth2',intfName2='r3-eth2', cls=TCLink, bw=1 )
    
    # Config IP
    h0.cmd("ifconfig h0-eth0 0")
    h0.cmd("ifconfig h0-eth1 0")
    h0.cmd("ifconfig h0-eth0 192.168.0.1 netmask 255.255.255.0")
    h0.cmd("ifconfig h0-eth1 192.168.5.2 netmask 255.255.255.0")
    
    h1.cmd("ifconfig h1-eth0 0")
    h1.cmd("ifconfig h1-eth1 0")
    h1.cmd("ifconfig h1-eth0 192.168.2.2 netmask 255.255.255.0")
    h1.cmd("ifconfig h1-eth1 192.168.3.1 netmask 255.255.255.0")
    
    # Config router
    """
    r1.cmd("echo > 1 /proc/sys/net/ipv4/ip_forward")
    r2.cmd("echo > 1 /proc/sys/net/ipv4/ip_forward")
    r3.cmd("echo > 1 /proc/sys/net/ipv4/ip_forward")
    r4.cmd("echo > 1 /proc/sys/net/ipv4/ip_forward")
    """
    r1.cmd( 'sysctl net.ipv4.ip_forward=1' )
    r2.cmd( 'sysctl net.ipv4.ip_forward=1' )
    r3.cmd( 'sysctl net.ipv4.ip_forward=1' )
    r4.cmd( 'sysctl net.ipv4.ip_forward=1' )
    
    # Add IP Address for Router
    r1.cmd( 'ip addr add 192.168.0.2/24 brd + dev r1-eth0' )
    r1.cmd( 'ip addr add 192.168.1.1/24 brd + dev r1-eth1' )
    r1.cmd( 'ip addr add 192.168.6.1/24 brd + dev r1-eth2' )
    
    r2.cmd( 'ip addr add 192.168.4.2/24 brd + dev r2-eth0' )
    r2.cmd( 'ip addr add 192.168.5.1/24 brd + dev r2-eth1' )
    r2.cmd( 'ip addr add 192.168.7.2/24 brd + dev r2-eth2' )
    
    r3.cmd( 'ip addr add 192.168.2.1/24 brd + dev r3-eth0' )
    r3.cmd( 'ip addr add 192.168.1.2/24 brd + dev r3-eth1' )
    r3.cmd( 'ip addr add 192.168.7.1/24 brd + dev r3-eth2' )
    
    r4.cmd( 'ip addr add 192.168.4.1/24 brd + dev r4-eth0' )
    r4.cmd( 'ip addr add 192.168.3.2/24 brd + dev r4-eth1' )
    r4.cmd( 'ip addr add 192.168.6.2/24 brd + dev r4-eth2' )
    
    
 #CLO2
    
    # Static Routing (host)
    h0.cmd('ip rule add from 192.168.0.1 table 1')
    h0.cmd('ip rule add from 192.168.5.2 table 2')
    h0.cmd('ip route add 192.168.0.0/24 dev h0-eth0 scope link table 1')
    h0.cmd('ip route add default via 192.168.0.2 dev h0-eth0 table 1')
    h0.cmd('ip route add 192.168.5.0/24 dev h0-eth1 scope link table 2')
    h0.cmd('ip route add default via 192.168.5.1 dev h0-eth1 table 2')
    h0.cmd('ip route add default scope global nexthop via 192.168.0.2 dev h0-eth0')
    #h0.cmd('ip route add default scope global nexthop via 192.168.5.1 dev h0-eth1')
    
    h1.cmd('ip rule add from 192.168.2.2 table 3')
    h1.cmd('ip rule add from 192.168.3.1 table 4')
    h1.cmd('ip route add 192.168.2.0/24 dev h1-eth0 scope link table 3')
    h1.cmd('ip route add default via 192.168.2.1 dev h1-eth0 table 3')
    h1.cmd('ip route add 192.168.3.0/24 dev h1-eth1 scope link table 4')
    h1.cmd('ip route add default via 192.168.3.2 dev h1-eth1 table 4')
    h1.cmd('ip route add default scope global nexthop via 192.168.2.1 dev h1-eth0')
    #h1.cmd('ip route add default scope global nexthop via 192.168.3.1 dev h1-eth1')
    
    # Static Routing (router)
    r1.cmd('route add -net 192.168.2.0/24 gw 192.168.1.2')
    r1.cmd('route add -net 192.168.3.0/24 gw 192.168.1.2')
    r1.cmd('route add -net 192.168.4.0/24 gw 192.168.6.2')
    r1.cmd('route add -net 192.168.5.0/24 gw 192.168.6.2')
    r1.cmd('route add -net 192.168.7.0/24 gw 192.168.1.2')
    
    r2.cmd('route add -net 192.168.1.0/24 gw 192.168.7.1')
    r2.cmd('route add -net 192.168.2.0/24 gw 192.168.7.1')
    r2.cmd('route add -net 192.168.3.0/24 gw 192.168.4.1')
    r2.cmd('route add -net 192.168.6.0/24 gw 192.168.4.1')
    r2.cmd('route add -net 192.168.0.0/24 gw 192.168.7.1')
    
    r3.cmd('route add -net 192.168.3.0/24 gw 192.168.2.2')
    r3.cmd('route add -net 192.168.4.0/24 gw 192.168.7.2')
    r3.cmd('route add -net 192.168.5.0/24 gw 192.168.7.2')
    r3.cmd('route add -net 192.168.6.0/24 gw 192.168.1.1')
    r3.cmd('route add -net 192.168.0.0/24 gw 192.168.1.1')
    
    r4.cmd('route add -net 192.168.1.0/24 gw 192.168.6.1')
    r4.cmd('route add -net 192.168.2.0/24 gw 192.168.6.1')
    r4.cmd('route add -net 192.168.5.0/24 gw 192.168.4.2')
    r4.cmd('route add -net 192.168.7.0/24 gw 192.168.4.2')
    r4.cmd('route add -net 192.168.0.0/24 gw 192.168.6.1')
    
    #Menjalankan iPerf dibackground proses
    #h1.cmd('iperf -s &')
    #h0.cmd('iperf -t 40 -c 192.168.2.2 &')
    
    
    net.start()
    net.build()
    info( '\n', net.ping() ,'\n' )
    CLI(net)
    net.stop()
    
    
if __name__ == "__main__":
    os.system('mn -c')
    os.system('clear')
    setLogLevel('info')
    routerNet()
    
 
       
    




   



    

