---
title: "CS4404 Mission 2"
date: "Nov 19, 2019"
author:
    - "David Larson"
    - "Ben Longo"
    - "Cole Winsor"
---

# Introduction
Domain Name System (DNS) is the backbone for how we use the internet today. Instead of using hard to memorize IP addresses to identify networked services and computers, DNS allows the use of human readable names which can be later translated to the IP address by a DNS server. This translation is a tiered process starting from a root DNS server, which identifies the different top level domains (TLD), going to the TLD DNS servers, and continuing to more and more specific DNS servers until the IP can be resolved. This process can be done by the client, but is usually done by an ISP DNS resolver, which will recursively contact the different DNS servers necessary to resolve the domain name. This process is preferable for clients because it means their computer doesn’t have to handle the resolving workload, and because the ISP resolver can cache common domains, speeding up the time it takes to resolve. Today domain names are nearly ubiquitously used; however, this extra layer of convenience can come with serious risks.

![Image description](https://d1.awsstatic.com/Route53/how-route-53-routes-traffic.8d313c7da075c3c7303aaef32e89b5d0b7885e7c.png)

In this report we first analyzed the different security goals of DNS, how to circumvent them, and how to defend these different attack vectors. In order to further our learning, we set up a testing network infrastructure in order to test these attacks and defenses. Specifically we looked at an example ISP who was attacking their clients, and the ways in which a defender could protect themselves against such an entity. We implemented several attacks against the clients, including DNS record forgery and a denial of service. Finally we implemented DNSSEC and DNS over a VPN in order to protect the client against these types of attacks from an ISP.

# Reconnaissance Phase

In order to properly serve the desired purpose, DNS must fit several security goals. The main security goals which DNS must meet are integrity and authenticity. In addition, availability (1), and more recently, confidentiality are secondary goals of DNS(2). 

Integrity and availability are important goals of DNS because the responses from DNS servers tell you the address of a desired service. If these goals are not met, users could be given incorrect addresses for the services they want, which in the best case could cause confusion or in the worst case cause them to relinquish confidential information (3). These security goals are especially important because of the distributed nature of DNS, which gives attackers many potential points to attack. For users, these security goals are important because they want to be directed to the correct service. This goal is important for DNS organizations as well, because if incorrect information is given, they will lose reputation and trust from users. Finally, this is also an important security goal for software companies, because if the integrity of DNS results isn’t protected, their users may be diverted from their site, and they could lose web traffic.

Attacks which subvert integrity and authenticity aim to modify stored records or modify sent DNS responses. The most common type of attack is cache poisoning(4). In this, the attacker sends spoofed responses to a DNS resolver so that the incorrect information is cached and sent to other clients. Although originally more restricted, Dan Kaminsky noticed additional flaws in DNS resolver caching that made cache poisoning much more dangerous. These flaws allowed the takeover of entire domains while also making the attack more reliable (5). One example of a cache poisoning attack on DNS caused many users of the crypto wallet MEW to be redirected to a phishing site, causing them to give up their login information (6).

DNSSec is the most common defense for integrity and authenticity. This extension to DNS uses a chain of signatures to allow a client to validate the authenticity of a DNS response by checking that it was signed by the correct DNS server (7). In addition, each record is signed, allowing verification of individual records. For each DNS server, there will be a public and private zone signing key (ZSK). The ZSK is used to sign each record, and these signatures become RRSIG records. In order to enable the chain of trust, an additional key pair is used which is called the key signing key (KSK). This key is used to create a signature for the ZSK. This signature then becomes a DNS record on the next level up DNS server. These keys and signatures, once propagated to the client, allowing the verification of the authenticity and integrity of each record.

Availability is also an important goal of DNS because the internet is extremely reliant on it’s DNS backbone (1). If an attacker is able to disrupt DNS, clients won’t be able to resolve host names, which means clients won’t be able to find the actual IP addresses for their requested services. This effectively brings down the internet, since IP addresses of specific services are rarely known by an end user. This security goal is important to all stakeholders. For users, the internet will become unusable if they don’t have access to DNS services. For DNS organizations, losing availability means that the service that they provide are down, negatively affecting their reputation. Finally companies hosting websites are also negatively by loss of availability because users can no longer reach their websites.

There are several ways in which availability of DNS can be attacked. Most of these attacks focus on different way of creating large computational loads for DNS servers. One example is NXDOMAIN flooding, where DNS servers are sent many requests for non existent domains (8). This type of request is computationally expensive for the server to handle, and can cause the servers to slow down and disrupt their ability to respond to legitimate requests. Phantom domain attacks are another type of attack which aim to slow down or crash DNS servers (9). The attacker sets up a subdomain which they configure to not respond or be slow to respond to DNS requests. They then flood a resolver with requests to this subdomain, forcing the resolver to maintain state for each request while waiting for the DNS. This has a similar effect to NXDOMAIN attack, causing resolvers to slow down. This list is not exhaustive as there are many other types of DoS attacks against DNS infrastructure.

The most popular way to protect DNS availability is by creating a DNS firewall (10). A DNS firewall can enable rate limiting to mitigate the impacts of these attacks, as well as configure rules to drop requests that are recognized as a part of a DoS attack.

Finally, confidentiality has recently become a concern of DNS (11). DNS traffic reflects the different places that each users goes on the internet. If an attacker can gain access to DNS data, it can affect a user’s browsing confidentiality. This security goal is mostly only important to users because their data is at risk in these types of attacks. Companies and DNS organizations do not have personal information transported over DNS, so they are unaffected by these attacks. These companies may even benefit from being able to track users browsing information.

Like availability, confidentiality can be compromised by a number of different types of attacks. One such attack is DNS server cache snooping, in which an attacker queries a DNS resolver to see if that specific record is cached (12). This allows an attacker to see if any users of that resolver have been to that domain recently. This attack is somewhat limited, but a more serious risk comes from a passive man-in-the-middle (MitM). Most DNS traffic is sent in cleartext which means a MitM, such as an ISP, can associate an IP with its DNS traffic, reflecting where on the internet it has visited (13). 

There are two common ways to protect an individual's DNS confidentiality. DNS over TLS (DOT) and DNS over HTTPS (DOH) (14) both provide confidentiality. These both have the same effect of encrypting the DNS traffic. This makes it so a MitM cannot inspect the body of a client's DNS requests, protecting the clients confidentiality. DOT and DOH are similar as they both use TLS as a basis, however the difference in the port used means that DOH provides more anonymous DNS traffic, while DOT gives maintainers more control over network security (14)

In addition to these security goals, DNS can also be misused for other types of attacks such as DDoS attacks. DNS is often used for reflection and amplification attacks. Reflection attacks allow an attacker to hide their attacking agent by pivoting off of an outside server (15). Amplification attacks are a type of reflection attack which uses the pivoting to increase the payload size of transmitted packets (16). DNS is particularly susceptible to be used for these attacks because they use UDP packets, which allows attackers to easily spoof response addresses and because responses are often far larger than the query (17). These attacks undermine the internets security goals of authenticity and availability, because these attacks use spoofed addresses to enable reflection, and the results of these attacks can bring down web services and can even slow traffic for other users.

To solve this, DNS servers often implement rate limiting, were a DNS server will start dropping requests if a certain limit is met. This makes it hard to reflect sufficient packets off DNS to affect the target (18). In addition many DNS providers are starting to move to DNS over TCP, which makes it harder to do reflection attacks because the TCP handshake makes it very difficult to spoof response addresses (19).

It is important to note that most of these attacks come from the perspective of an outside attacker. For the CEO’s vision to be achieved, much less work needs to be done because an ISP has privileged access to network infrastructure. For instance, it would be pointless for the CEO to use cache-poisoning to attack a DNS resolver because he controls the resolver and can just make it serve incorrect records. The ISP can easily control availability because now that net neutrality is no more, the ISP can selectively block any traffic, including any webpages server or DNS servers. Finally, your ISP can see any of your traffic and therefore can easily see where you're browsing from your DNS traffic. If proper protections are not made, an ISP essentially has full control over every aspect of your web experience. For example, many ISPs, when you use their resolver, won’t send you NXRECORD for an invalid domain (20). Instead, they will send you a valid record to a webpage filled with ads, which is a form of DNS hijacking. In addition, many governments implement internet censorship by requiring their ISPs to redirect and block traffic to certain domains (21). China’s Great Firewall is the largest example of this. Most ISPs also track their users traffic using DNS requests. Some even use this for nefarious purposes such as targeted ads (13). 

Overall, current DNS infrastructure has serious flaws, allowing many vectors of attack. Attackers, even from an outside perspective, can attack each security goal of DNS, subverting the purposes for which it was implemented. In addition, DNS can be misused to launch attacks against other networked services. ISPs are a major part of DNS infrastructure because they provide DNS resolvers to their customers, but this privileged perspective gives ISPs a lot of power over internet use. As the old saying goes, with great power comes great responsibility, and many ISPs are not being responsible with DNS infrastructure, subverting the security goals which need to be upheld for DNS.

# Infrastructure

Several key pieces are needed to faithfully replicate the important aspects of an ISP and their DNS infrastructure. Most importantly, all traffic gets routed through the ISP and all DNS requests (by default) get sent to the ISP's recursive DNS resolver.

As we are on an isolated network, we must also create a complete DNS setup (root server included). 

To fully demonstrate the impacts of DNS attacks, we also need to deploy a couple of web servers hosting actual content. Thus we require the following servers: 

* An authoritative root DNS server
* An authoritative TLD DNS server 
* A web server outside of the ISP's network 
* A web server within the ISP's network 
* A router for the ISP
* A recursive DNS resolver for the ISP 
* An end client within the ISP's network

In addition, for our defense we need an additional web server
* VPN server outside of the ISP's network

Given that we only have 6 servers, we chose to co-host the router, bombast web server, and DNS resolver for the ISP onto a single machine. We assign these servers to hosts as follows: 

1. The end client 
2. The internal web server (`bombast.zoo`) / The ISP recursive DNS resolver / router 
3. VPN server
4. The external web server (`other-isp.zoo`)
5. The authoritative DNS server for `.zoo` 
6. The root DNS server 

The client machine is configured to use the ISP's DNS resolver. In addition, all of it's traffic is router through the ISP's router. The web server, DNS resolver and ISP router are all co-hosted. The web server is a simple python http server with a single path '/'. The DNS resolver is a bind resolver. The router is implemented by enabling ipv4 forwarding and disabling ICMP redirects. The VPN server is a part of our defense and will be discussed later. The Zoo DNS server is a TLD for .zoo. This is implemented using a knot DNS server. Finally, the root DNS server is also implemented using knot DNS servers. 

In order to make deployment easy, we have created debain packages for each functional component. By running `make`, these packages can be compiled, and running `./deploy` relevant packages will be copied to and installed on each VM. 

A successful deployment will look like this 
<script id="asciicast-282729" src="https://asciinema.org/a/282729.js" data-speed="2" async></script>


Instructions on how to manually deploy and verify the infrastructure can be found in appendix D

# Attack 

For our attack phase, we implemented several attack which leveraged the Bombast ISPs DNS resolver to control the clients DNS traffic. This is implemented using a single debian package which is deployed in the deploy script and can be configured in by following instructions in Appendix B. These attacks both allowed redirecting and blocking the clients attempts to access the other-isp web page. Redirecting was implemented by spoofing the DNS response to contain the bombast web page's IP when the other-isp's was requested. Achieves the CEO's vision of altering customers traffic by circumventing DNS integrity and authenticity goals. Blocking access can be configured in 2 modes, a 'silent' nonexistent record attack, which tells the client that the other-isp web page doesn't exist, and a 'drop' mode which refuses to respond to the client with other-isp's address and lets the client time out. The first of these attacks also achieves the CEO's vision by circumventing availability without the customers knowledge. 

In addition to these attacks, we have implemented an additional layer which drops customer DNS traffic in the ISP network. This is implemented using a single debian package which is deployed in the deploy script and can be configured in by following instructions in appendix B. This DoS attack means that client cannot run their own resolvers and are forced to either not use DNS or use the the ISP's resolver.

The attack deployment and validation has been full automated for convenience. Once the infrastructure has been setup, the `./demo_attack` script will run and validate each attack.

A successful run will look like this 
<script id="asciicast-282728" src="https://asciinema.org/a/282728.js" data-speed="2" async></script>
The full output of the script can be seen in Appendix E.

Instructions to deploy and validate the attacks implemented here can be found in appendix B.

## IPTables DNS Block Attack

If a client becomes aware that Bombast's DNS servers are returning errant or misleading records, the client could easily choose to use a different DNS server. However, since DNS packets are sent in plaintext over UDP on a known port, and Bombast controls the router through which the client accesses the internet, Bombast can still easily interfere with these DNS requests. We were able to implement this attack by adding a single rule to `iptables`.

```
/sbin/iptables -I INPUT -p udp --dport 53 \
               -m string --hex-string "|09|other-isp|03|zoo|" \
               -j DROP
```

The above command gives us the desired effect. The -I flag specifies that the rule is to be inserted at a given index which we did not specify, defaulting to the top of the chain. We then specify that we want the rule to be for incoming traffic with `INPUT`, and specify we only want UDP packets with `-p udp`. We then select the port with `--dport 53`. The next chunk, `-m string --hex-string` tells `iptables` to filter packets containing a given string, which we encode with `|09|other-isp|03|zoo|`. The digits between the strings represent the length of the immediately following string. We are using `other-isp.zoo` to represent the web server of a competing ISP. Finally, `-j DROP` specifies that we want to drop any packets that match our criteria.

This attack results in a DOS for a client trying to reach this website, since the router drops all packets containing 'other-isp.zoo'. The client will receive DNS timeouts when trying to reach this website since the packets will never make it to the DNS server.

# Defense

We have implemented a few different types of attacks in this mission. One attack is at the DNS level, in which we return forged DNS records upon a request to our server. The logical solution to this is to mandate the use of DNSSEC. If a client mandates that a DNS response be digitally signed, then the client can be completely sure that the record is authentic and came from a trusted DNS server.

However, because the attacker is the ISP themselves, additional protections are needed. Even with DNSSEC, it is usually expected that the resolver does the signature validation. This means that it is unlikely that a customer would notice false records being sent from the resolver, making the first level of attacks implemented still effective in most cases. To get around this we have created a DNS resolver on the client. By self hosting, the client can trust the signature validation and records from this resolver.  

However, one of the attacks Bombast implemented at the network level drops all DNS traffic involving specific domains. In order to defend against the denial of service attack we can turn to DNS over a secured channel. Since plain DNS queries and responses are sent over UDP in plaintext, Bombast can easily filter our packets to prevent us from visiting certain websites. If we send our traffic through a VPN, Bombast can no longer filter or see the contents of our packets. This would leave them with the option to either allow all traffic, or block all traffic, which is a much less powerful attack.

The defense deployment and validation has been full automated for convenience. Like for the attack phase, the `./demo_attack` script will validate each defense for the different possible attacks. 
You can see the complete output in Appendix E. 

If you want to manually setup the defense, the defense packages for dnssec can be installed with the following commands.

`ssh 10.4.9.6`

`dpkg --remove root-dns-setup`

`dpkg --install root-dnssec.deb`

`exit`

`ssh 10.4.9.5`

`dpkg --remove zoo-dns-setup`

`dpkg --install zoo-dnssec.deb`

`exit`

`ssh 10.4.9.1`

`dpkg --install client-resolver.deb`

The VPN can be setup with 

`ssh 10.4.9.1`

`dpkg --install vpn-client.deb`
And bringing up the tunnels as documented in the specifics. 

The steps for fully manual setup of DNSSec can be found in appendix A. The steps for fully manual setup the the VPN can be found below

## VPN

If a client was so inclined, they could employ a VPN to protect them and their packets from the intrusive ISP. Doing so would tunnel all of their traffic through a remote server where it is encrypted and their IP address is hidden. This would render the ISP powerless over your packet traffic. Our team attempted to implement this to show a fully successful defense against any kind of attack from the ISP. We chose to use "Dead Simple" VPN (DSVPN), and to install it on our host 3. DSVPN is supposed to work out of the box with minimal configuration, however we found that the architecture of our LAN posed some difficulties in setting it up properly.

Firstly, we had to compile the code from source on one of the zoo lab VMs so that we could execute the resulting binary. Then we had to generate a key for use in symmetric encrpytion, which we did with `dd if=/dev/urandom of=vpn.key count=1 bs=32`. Once we had the binary and our key, we ran the server with 
`./dsvpn server vpn.key`.

The first problem we ran into was that DSVPN couldn't automatically detect which network interface it needed to use. To fix this we dove into the source code and manually told it which interface it needed to use:

```
context.ext_if_name = "eth0";
```

At this point our server ran successfully. We then moved onto setting up our VPN client on host 1. Allegedly we should have been able to connect to our server with `./dsvpn client vpn.key 10.4.9.3`. However, we were met with a few more issues. The first issue was that DSVPN complained that it didn't know which external gateway IP to use, since the network doesn't have a router. We again dove into the source code and hardcoded this: 

```
ext_gw_ip = "10.4.9.3";
```

This solved that issue. However, it seemed that our VPN was working _too_ well. We immediately lost our ssh connection. We believe this is because the VPN cient began tunneling _all_ traffic, including ssh. 
We found an undocumented compile flag within the source code that turned off the automatic route creation, however when we attempted to manually create the routes, the peered tunnel would set itself up properly and DSVPN. 

After determining that DSVPN was anything but dead simple, we aimed for an even simpler solution: ssh tunnels. People don't generally use this sort of thing because it has abysmal performance: every packet gets wrapped up in another packet which can add a pretty insane amount of overhead. 

First we create a tunnel interface in `/etc/network/interfaces` on both the client and the VPN host. 
```
# The client (some fields omitted)
iface tun0 inet static
    address 192.168.9.1
    pointopoint 192.168.9.3
    netmask 255.255.255.255

# The server (some fields omitted)
iface tun0 inet static
    address 192.168.9.3
    pointopoint 192.168.9.1
    netmask 255.255.255.0
```
Note that we give the tunnel interfaces IP addresses outside of the LAN. 
The interfaces are brought up with `ifup tun0`.

We create a keypair on the client with `ssh-keygen` and then add the pubkey to the VPN hosts `authorized_keys` file. After this is done creating the ssh tunnel is easy:
```
ssh -N -f -w 0:0 10.4.9.3
```
The `0:0` lets `ssh` know that it should use `tun0` on both sides of the connection, `-N` let's it know we don't actually want to execute any commands. 

Once the tunnel is up, we have to let our routing tables know what traffic to shoot through the tunnel. For sake of demonstration, we chose only to shoot the DNS traffic through the tunnel by hardcoding those hosts, but a real VPN user would likely send _all_ traffic through the VPN to maximize privacy. 
```
ip route add 10.4.9.5 via 192.168.9.3
ip route add 10.4.9.6 via 192.168.9.3
```

This will make our traffic get out to the other side of the tunnel, but currently it won't go anywhere from there because we haven't told the server what to do with the packets coming in over the tunnel. We want to NAT the connections out so that it looks like the traffic is coming from the VPN host and responses get sent back over the tunnel. We can accomplish this via `MASQUERADE` nat on `eth0` and doing a `FORWARD` from `tun0` to `eth0` like so 
```
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -A FORWARD -i tun0 -o eth0 -j ACCEPT
```

This completes the DNS over VPN setup.

# Conclusion 

As this exploration has demonstrated, DNS is only as strong as it's weakest component. DNS must protect each security goal: Integrity, Authenticity, Availability, and Confidentiality. As outlined in the reconnaissance phase, there are a variety of attacks which together can overcome all of the security goals in DNS. In particular, the privileged view of ISPs give them a prime point of attack.  While defenses have been developed to each of these attacks, DNS providers are still deploying these, leaving DNS vulnerable to attacks. Our demonstration provides ample evidence for how insecure current DNS is on an accurate test infrastructure. However, in our defense phase we have also shown how clients and DNS servers can be nearly completely secured if they follow proper steps to protect themselves.  

# Bibliography

1. https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-81-2.pdf
2. https://www.internetsociety.org/resources/deploy360/dns-privacy/intro/
3. https://blog.avatao.com/DNS-privacy-and-security/
4. https://adventuresinsecurity.com/Papers/DNS_Cache_Poisoning.pdf
5. http://people.scs.carleton.ca/~soma/pubs/acowpert-asia-2010.pdf
6. https://techcrunch.com/2018/04/24/myetherwallet-hit-by-dns-attack/
7. https://www.icann.org/resources/pages/dnssec-what-is-it-why-important-2019-03-05-en
8. https://www.netscout.com/what-is-ddos/dns-nxdomain-flood
9. https://resources.infosecinstitute.com/attacks-over-dns/#gref
10. https://www.cloudflare.com/learning/dns/dns-security/
11. https://www.internetsociety.org/resources/deploy360/dns-privacy/intro/
12. https://support.microsoft.com/en-us/help/2678371/microsoft-dns-server-vulnerability-to-dns-server-cache-snooping-attack
13. https://arstechnica.com/tech-policy/2019/09/isps-worry-a-new-chrome-feature-will-stop-them-from-spying-on-you/
14. https://www.thesslstore.com/blog/dns-over-tls-vs-dns-over-https/
15. https://www.cloudbric.com/blog/2015/03/reflection-attacks-and-amplification-atttacks/
16. https://www.imperva.com/learn/application-security/snmp-reflection/
17. https://www.imperva.com/learn/application-security/dns-amplification/
18. https://www.a10networks.com/blog/how-defend-against-amplified-reflection-ddos-attacks/
19. https://www.tripwire.com/state-of-security/security-data-protection/cyber-security/dns-amplification-protecting-unrestricted-open-dns-resolvers/
20. https://securitytrails.com/blog/dns-hijacking
21. https://www.cc.gatech.edu/~pearce/papers/dns_usenix_2017.pdf


# Appendix A: Setting and Verification of DNSSEC
The first line of defense that we implemented was DNSSEC. This was enabled on both of our knot DNS server, the root and zoo TLD. The following steps were followed to enable this

## Zoo TLD DNS server
To enable the DNSSec on the Zoo DNS server, first SSH into the Zoo DNS server, which in our case is at 10.4.9.5. Become the root user and proceed with the following steps. 
Create a new directory for the key managment database
```
root@host5:~#  mkdir -v /var/lib/knot/kasp
mkdir: created directory '/var/lib/knot/kasp'
```
Move to the newly created directory. Initialize the key managment database. Verify that it has initialized by printing the contents of the directory.
```
root@host5:~# cd /var/lib/knot/kasp
root@host5:/var/lib/knot/kasp# keymgr init
root@host5:/var/lib/knot/kasp# ls
keys  keystore_default.json  policy_default.json
```
Create a new key managment policy. 
```
root@host5:/var/lib/knot/kasp# keymgr policy add rsa algorithm RSASHA256 zsk-size 1024 ksk-size 2048
manual control:   false
keystore:         default
algorithm:        8
DNSKEY TTL:       1200
KSK key size:     2048
ZSK key size:     1024
ZSK lifetime:     2592000
RRSIG lifetime:   1209600
RRSIG refresh:    604800
NSEC3 enabled:    false
SOA min TTL:      0
zone max TTL:     0
data propagation: 3600
```
Add this policy to the zoo zone
```
root@host5:/var/lib/knot/kasp# keymgr zone add zoo policy rsa
```
Verify this is correctly configured
```
root@host5:/var/lib/knot/kasp# keymgr zone show zoo
zone: zoo
policy: rsa
keys: 0
```
open the /etc/knot/knot.conf file and modify the zone to look as follows 
```
zone:
  - domain: zoo
    storage: /var/lib/knot/zones
    file: "zoo.zone"
    kasp-db: kasp
    dnssec-signing: on
```
Verify this by printing the file. It should look the same as below
```
root@host5:/var/lib/knot/kasp# cat /etc/knot/knot.conf
server:
    listen: 0.0.0.0@53
log:
  - target: syslog
    any: info
zone:
  - domain: zoo
    storage: /var/lib/knot/zones
    file: "zoo.zone"
    kasp-db:  /var/lib/knot/kasp
    dnssec-signing: on
```
Restart knot. Verify that the server restarted correctly.
```
root@host5:/var/lib/knot/kasp# systemctl restart knot
root@host5:/var/lib/knot/kasp# journalctl -fu knot
```
If you see similar output, then your knot server is now properly configured with DNSSec
```
systemd[1]: Started Knot DNS server.
knotd[2900]: info: Knot DNS 2.1.1 starting
knotd[2900]: info: binding to interface ‘0.0.0.0@53’
knotd[2900]: info: loading 1 zones
knotd[2900]: info: [zoo] zone will be loaded, serial 0
knotd[2900]: info: starting server
knotd[2900]: info: [zoo] DNSSEC, executing event ‘generate initial keys’
knotd[2900]: info: [zoo] DNSSEC, loaded key, tag 17164, algorithm 8, KSK yes, ZSK no, public yes, active yes
knotd[2900]: info: [zoo] DNSSEC, loaded key, tag  5308, algorithm 8, KSK no, ZSK yes, public yes, active yes
knotd[2900]: info: [zoo] DNSSEC, signing started
knotd[2900]: info: [zoo] DNSSEC, successfully signed
knotd[2900]: info: [zoo] DNSSEC, next signing on 2019-11-25T22:35:54
knotd[2900]: info: [zoo] loaded, serial 0 -> 2019111301
knotd[2900]: info: server started in the foreground, PID 2900
knotd[2900]: info: remote control, binding to ‘/run/knot/knot.sock’
knotd[2900]: info: [zoo] zone file updated, serial 2019111300 -> 2019111301
```
Verify changes ahve been made to the /var/lib/zones/zoo.zone file
```
root@host5:/var/lib/knot# cat /var/lib/knot/zones/zoo.zone
;; Zone dump (Knot DNS 2.1.1)
zoo.                	3600	SOA	zoo-ns.net. fake.nope.com.zoo. 2019111301 1800 900 604800 86400
zoo.                	3600	DNSKEY	256 3 8 AwEAAbODrXe/9tiWkwSnlvQ8pSkuZYWD4t8Cvpq00ssAZ7huqw7ZBqMCPB1ka3r66jdGekOW/2iJhZxv3oM4JDsmdTL4BNeGw2lcmwPqyHw6dU1mmjow+5eRGK/6ABNz99O/Gv59zRYG0PoFVx/bkzXO+6hZ8dQXNFLB/VncWqF7X9SP
zoo.                	3600	DNSKEY	257 3 8 AwEAAZbQcik8qpSKQRAbz42ZmAj0Ct/e7wiE4z8BRUNuyYqw6N7kuIqvog1JHAErV5Z01H5KcpUh+rx6be3mawBWDyRQqPc0poZ0rX2QB0l1/Xfp/qI9DXYIC/cN07wQmjNBscluFN+gm7yEuuoGlfdfRCB7e0gCyz3mfCjMQ3lk+meuTTPHIfBXFNxYZblz542z63Rl6Mz9EiOratEvamiUoFSdVVltocX0/hAFwHu2lh07359fSsoyzQcnm8unBLKukm7aaD22dmrY/bEp2baCE2kzOdiIiSsPRyO7rSO0EEwx8PjQOClGKJ7FXWrVO0GIflml0hETFPaPO0Acz8rzYJs=
bombast.zoo.        	3600	A	10.4.9.2
other-isp.zoo.      	3600	A	10.4.9.4
;; DNSSEC signatures
zoo.                	3600	RRSIG	SOA 8 1 3600 20191203033554 20191119033554 5308 zoo. HZY80bt1ssFlLtaw5xV6idLeO0U9B/ZUS7mxcDOAnSAtdIvhHQKqS55mfANj5mhdFfNKNDnHRc0WHAkjCKcbIKqeju+PFlUbKogjoluyWGo2sa//k2p+RI1AlzxB/6ATrXiDEbEnAqkH0qXmlsiIQtmjRqI+sTdHpf0oTvRJIEo=
zoo.                	86400	RRSIG	NSEC 8 1 86400 20191203033554 20191119033554 5308 zoo. brm8B2Kr+3+GyO2+xxCGAQ4KgxxHFHiURUABiMs09HkBV8W0+qo5C3JB/O3XqUx0FzKK99GsjfjN4VSFOdvOLPt1F1YGLbwMOp7eorrbSKF4Nd8atTO2yNXNDLQjoE/LjLzDlUwG+NUbHTkSzlKnHZXF4NActsHDkBdUrFxesUM=
zoo.                	3600	RRSIG	DNSKEY 8 1 3600 20191203033554 20191119033554 17164 zoo. T1cuuvF2k19TGpbuqhhOdi9IEfxiNfJwRmUBt/NOjWfb7ZyibxZuMcvhEdoZcVxwxQXP/iYKEq+rMTu3G1uCSBMVjgsWrLPWuhwLw4YxoufMixY9SEwhVjqnpM2HN9IMLTIvQArsuEr3FtGOxEoWr/8WVmBMgZPFmyZ+CaE9xpYJfe2ljyEKeIXqzmTg54mMAYhjLo9LrRpywtE74tTfmfQ9uwxS1evSeFHZ6OoCweM6SYIFfFivZt8/pPQz5p8KPXZfq4PJ/cba7bubQz5DysRTEbTqKHJWtKg5NdClwcPlAwZ2szLDDnvjmmg0N54ZmHWtEUAleRTOvZA0LQjR6A==
bombast.zoo.        	3600	RRSIG	A 8 2 3600 20191203033554 20191119033554 5308 zoo. LqSPUIC2gCFHkp+5OHNsqroBRH2/nm/UuPGaEtoIV3fuZ9/kkSrQx3heEGjW1gDjAsRECp4hSRhIeQBJtT4mWOg1D72V8+RZR4D4AvpfCZ4B/vGZ4ZMwdnfjAXB5ase9e2TNWy57NTs+2vfMYtCjXIxNG+mLItO448uCNHqQQ7c=
bombast.zoo.        	86400	RRSIG	NSEC 8 2 86400 20191203033554 20191119033554 5308 zoo. ldtosLONWuoZ3jrwrUENB9lh0HVInE2gcJSPtAREArr+EOSAapCuGZi7SXuH4TT5yN3rfIqURbsEg0+wYFv+SfRA0BudpnhXJUypFapvXygp2IQgcZgkYGCPr1PT0F/0oC9usGof23ONPFud0royN0yeVNgG/ZYphfY57OCEd48=
other-isp.zoo.      	3600	RRSIG	A 8 2 3600 20191203033554 20191119033554 5308 zoo. Qb09XIJFf+oa2C9T6aGIZzYgzzAUcj2pwZ/9HGIla+18Zd6wCPeU7Vb2UReuJrFy3EvzrUDyMcfTVkc1Q6rl0Gd5aNxAKTEyHCYD3XiTV/t3DB36g73O+ciFl3W/GgzeonaIWJTs/263pGA0/amyf6pQHx9acC2WclC8dg7WKiU=
other-isp.zoo.      	86400	RRSIG	NSEC 8 2 86400 20191203033554 20191119033554 5308 zoo. cn/uoH66kGfOk55OOnhnOCElYiWYBqkruo8x6nPIthOLViOszyIZ7L84OPbIP2EMcquKpj38r2kDarTv3e+mLcuVgVISJ0r/gIVGIh9Fb/EYjYR1lax7W3m0X6X2mtb8OCl/fPB14yJx3wHJ2VpklGjscm55/6/xbyGg6n/HLqs=
;; DNSSEC NSEC chain
zoo.                	86400	NSEC	bombast.zoo. SOA RRSIG NSEC DNSKEY
bombast.zoo.        	86400	NSEC	other-isp.zoo. A RRSIG NSEC
other-isp.zoo.      	86400	NSEC	zoo. A RRSIG NSEC
;; Written 15 records
;; Time 2019-11-18 22:35:54 EST
```
Now we need ot get the DS records which will be records on the root server. Print the current keys being used.
```
root@host5:/var/lib/knot/kasp# keymgr zone key list zoo
id 3de38db168bb60b0f833340af922234b56653021 keytag 17164
id 27c55aeeaa6d75d8c033b116d53cd80027052b1f keytag 5308
```
The key signing key (KSK) should be the first of the two keys, but this can be verified by running `ls -la ./keys` and matching the file name of the larger file with the id of a key above. The KSK has a size twice that of the zone signing key (ZSK). Now print the DS records associated with the KSK (notice the number used is the keytag from the KSK). **Copy these records and save them for a later step**
```
root@host5:/var/lib/knot/kasp# keymgr zone key ds zoo 17164
zoo DS 17164 8 1 27c38a96336331e25a55ae95854799c14129475a
zoo DS 17164 8 2 2dd0f8f33b772336d246b98b32a56a449f2afa20097baff5d2ebd0daccf27c78
zoo DS 17164 8 4 34e11eef1b26f4cf988e3abca1271458287c4e53a36c43e1adc1c2a225beca7a2504b872de29a96fc85f9714d82b0355
```

## Root DNS server
To enable the DNSSec on the Root DNS server, first SSH into the Root DNS server, which in our case is at 10.4.9.6. Become the root user `# su` and proceed with the following steps. 
Create a new directory for the key managment database
```
root@host6:~#  mkdir -v /var/lib/knot/kasp
mkdir: created directory '/var/lib/knot/kasp'
```
Move to the newly created directory. Initialize the key managment database. Verify that it has initialized by printing the contents of the directory.
```
root@host6:~# cd /var/lib/knot/kasp
root@host6:/var/lib/knot/kasp# keymgr init
root@host6:/var/lib/knot/kasp# ls
keys  keystore_default.json  policy_default.json
```
Create a new key managment policy. 
```
root@host6:/var/lib/knot/kasp# keymgr policy add rsa algorithm RSASHA256 zsk-size 1024 ksk-size 2048
manual control:   false
keystore:         default
algorithm:        8
DNSKEY TTL:       1200
KSK key size:     2048
ZSK key size:     1024
ZSK lifetime:     2592000
RRSIG lifetime:   1209600
RRSIG refresh:    604800
NSEC3 enabled:    false
SOA min TTL:      0
zone max TTL:     0
data propagation: 3600
```
Add this policy to the zoo zone
```
root@host6:/var/lib/knot/kasp# keymgr zone add . policy rsa
```
Verify this is correctly configured
```
root@host6:/var/lib/knot/kasp# keymgr zone show .
zone:
policy: rsa
keys: 0
```
open the /etc/knot/knot.conf file and modify the zone to look as follows 
```
zone:
  - domain: .
    storage: /var/lib/knot/zones
    kasp-db: /var/lib/knot/kasp
    file: "root.zone"
    dnssec-signing: on
```
Verify this by printing the file. It should look the same as below
```
root@host6:/var/lib/knot/kasp# cat /etc/knot/knot.conf
server:
    listen: 0.0.0.0@53
log:
  - target: syslog
    any: info
zone:
  - domain: .
    storage: /var/lib/knot/zones
    kasp-db:  /var/lib/knot/kasp
    file: "root.zone"
    dnssec-signing: on
```
Restart knot. Verify that the server restarted correctly.
```
root@host6:/var/lib/knot/kasp# systemctl restart knot
root@host6:/var/lib/knot/kasp# journalctl -fu knot
```
If you see similar output, then your knot server is now properly configured with DNSSec
```
knotd[2093]: info: starting server
knotd[2093]: info: [.] loaded, serial 0 -> 2019111300
knotd[2093]: info: server started in the foreground, PID 2093
knotd[2093]: info: remote control, binding to '/run/knot/knot.sock'
knotd[2093]: info: stopping server
knotd[2093]: info: updating zone timers database
systemd[1]: Stopping Knot DNS server...
knotd[2093]: info: shutting down
systemd[1]: Stopped Knot DNS server.
systemd[1]: Started Knot DNS server.
knotd[2860]: info: Knot DNS 2.1.1 starting
knotd[2860]: info: binding to interface '0.0.0.0@53'
knotd[2860]: info: loading 1 zones
knotd[2860]: info: [.] zone will be loaded, serial 0
knotd[2860]: info: starting server
knotd[2860]: info: [.] DNSSEC, executing event 'generate initial keys'
knotd[2860]: info: [] DNSSEC, loaded key, tag  8731, algorithm 8, KSK yes, ZSK no, public yes, active yes
knotd[2860]: info: [] DNSSEC, loaded key, tag 26920, algorithm 8, KSK no, ZSK yes, public yes, active yes
knotd[2860]: info: [.] DNSSEC, signing started
knotd[2860]: info: [.] DNSSEC, successfully signed
knotd[2860]: info: [.] DNSSEC, next signing on 2019-11-25T22:49:00
knotd[2860]: info: [.] loaded, serial 0 -> 2019111301
knotd[2860]: info: server started in the foreground, PID 2860
knotd[2860]: info: remote control, binding to '/run/knot/knot.sock'
knotd[2860]: info: [.] zone file updated, serial 2019111300 -> 2019111301
```
Verify changes have been made to the /var/lib/zones/root.zone file
```
root@host6:/var/lib/knot/zones# cat root.zone
;; Zone dump (Knot DNS 2.1.1)
.                   	3600	SOA	root.net. fake-email.doesntexit.com. 2019111302 1800 900 604800 86400
.                   	3600	NS	root.net.
.                   	3600	DNSKEY	256 3 8 AwEAAeNaU9QWXmdCsTd1IloFEeVCaAqwyFihyEL54iFaHq0rVA5cufpe0O3/ib1uJzWUQIhGcTvYrSX6G6lxKjs9TFnOOBSDhTbms3P5OE9YCqk/TeqsEGyQmpe0mjxSPMmagQkm3SMmZXgTTZgCy1jXMjXHgdA0ANh25vE0XLAa2phZ
.                   	3600	DNSKEY	257 3 8 AwEAAZzXszNlsZU3XRWNXvfbIlGvfhuMMfgxIB5JfK7ZdmZyIyjTIejErYPmOn+CAIxpnIz2CGmQ7eN1lPkoCCNUlaWZTuwBEhiTELu4z986ptbea92g5zMqwEMOhK7DRTiMAPQUoslKyNZ7tCkR5o2sgUehakVaOW+fePDWXBGL2rr3s1iRZv95NaFWqs2Uxmo+ACR+opFsjwKSzkAdQPvhqzqtMxVR1W702yKOQL5XPws718vKi0k31bVihc52+lMIYJvH8kRvvQONP/Bqhg3j6lukOTTGJqPfkSN6CU83j+TXdkcNdcRu3Iyvt/hxqkudPsnj6Isbt6pxVrttQxjwxiM=
root.net.           	3600	A	10.4.9.6
zoo-ns.net.         	3600	A	10.4.9.5
zoo.                	3600	NS	zoo-ns.net.
zoo.                	3600	DS	17164 8 1 27C38A96336331E25A55AE95854799C14129475A
zoo.                	3600	DS	17164 8 2 2DD0F8F33B772336D246B98B32A56A449F2AFA20097BAFF5D2EBD0DACCF27C78
zoo.                	3600	DS	17164 8 4 34E11EEF1B26F4CF988E3ABCA1271458287C4E53A36C43E1ADC1C2A225BECA7A2504B872DE29A96FC85F9714D82B0355
;; DNSSEC signatures
.                   	3600	RRSIG	NS 8 0 3600 20191203034900 20191119034900 26920 . gSHj+84bAYYpd9W37kI9itu1mu5g1aIPugp8tUBgm2FMVWQ4MyOqSzpMLZIbuomGQ6BTr5Ld8iAnwwQVnkD4DzALLNb1X8rUSynEO1m60DYpJ7bBswu115ZOKwzFCgo6/NV+h4VX5Ehbs31blpAg8k/e3Hp4IXz0wvmMv7amZzo=
.                   	3600	RRSIG	SOA 8 0 3600 20191203035037 20191119035037 26920 . R5OyhQmw7XMUeRkRRmod9YAu8+qZRVAUJx4NCND1cZzL3ozIpEepbZM2Dt6c5LEme5/0B3Btt1Rxx9Fj1Lhn7lsdECyE8QlMT9tKpq4WuKdDF0I/mHtbUnx4dPk8D/QYewJdR9NLDaHcGWWcZ9U+3ACnckCGbUG28BNeRlVGjZ4=
.                   	86400	RRSIG	NSEC 8 0 86400 20191203034900 20191119034900 26920 . sFwx1xvvrszQfR6JaSvKaCjv5Ki5M7N/mpJPpJhkMDVJyj7E2hMr8xyaNfHTHQwg0/RyAw3mNtjIhrp+0QSjt2shhF/2zKjipv3S6CGOrpuwMVvbgDJR/M0fP6cJ+08QHBWRzL4gglgqkNC3svZs/gc69FvctOJl2yDYsOvu/3M=
.                   	3600	RRSIG	DNSKEY 8 0 3600 20191203034900 20191119034900 8731 . RQrQ8ilC+mu1qd79EAq5JCbNecdLO/V9L5BeQ1Kxj2qsTl4bGG5B6fJPfsmVv6IwPVaN/GRfjsguAOeFmShyPyku/FEVROsDmaDcR3v0D5p7cw+Hf0BzD2CZBjmbj2zaREoaXzsCQ9Qjxuuq1kGt1njNQvKi6CzKww6sPZSPJbMeqXupBIC4/FgpvFswFroi/jTalkJN4OigG5Fxg/rvqKqX0N61QLH1+ds0aalWGfP5AHWO4ab+owOYXFRSRX8KmkNVIdGiy87r9A+RGMFqMXQ1O0quIyncpNI/yiPRymTibdEsopiPDzzBlDxEXR9Qfm0LzVje4X9AJZwQ4HMtww==
root.net.           	3600	RRSIG	A 8 2 3600 20191203034900 20191119034900 26920 . LKbn2EqbfeJbQTh0Dn0RYqmqXZ/WeW3VEvQlGnYEqn5HEFtPafv0ZQ/7ryF05Kj73g+ZNzxv1082P1/zkK38yQzoRHkVvw6/LBpdoClmsxvHOEeLrqw+DWTdSJdkdnlR6lvg70lrHH1PKdnP9VuG+IWslnDSI9dtO0v/GSPF36c=
root.net.           	86400	RRSIG	NSEC 8 2 86400 20191203034900 20191119034900 26920 . BUncIxLGhqlKXgm7+kxhfVc7+C9bEp3S4w+YSvwGm6xR7raQOsro5s1ZkZvoQLLnzsplueN1tg3vNo9H7BHc6AnHhbzen+vtkSL+sSwVa7CnHKwCmoZRUNM4eqCCb3/HjZYjpH+U2XV59LgrQunHWTVg9FCwUOAQU5w4zQnRfz0=
zoo-ns.net.         	3600	RRSIG	A 8 2 3600 20191203034900 20191119034900 26920 . kVgcC7TdTh8MQ1bImCOEYDZ6zdcRQ8T2JExJ3r+Wgzo4Ahl+Ye2VCzl3l6U76eyB9x/adZyc7RWnU3z8JhKQH7WoEuc+nFIhxu6g5qPt9WfQ+X05wf2Uu6GUah7p6C3yKd5FWjO9GnqBXyqqQ1UKltKzh6IfUR/OqNev8+9icT4=
zoo-ns.net.         	86400	RRSIG	NSEC 8 2 86400 20191203034900 20191119034900 26920 . G3WKdRv2F0JoAhskn8KyC6lxW3QabtigUoyoaTD69yMvOYPMdqQh1R59fJkyNTQ+Tp4RufeNFGzf8udIMCqXLvfjOpK4ITBn6ZulAMGRquuzHfusr16nb/UF0l/pyuFdQUybOiaORNVnQivc4Bw2Mel0HtQmxLQ44Ni+0Zs0W/M=
zoo.                	3600	RRSIG	DS 8 1 3600 20191203035037 20191119035037 26920 . dtC2frPDETNzePpyr7hCKbp+wRX7xzPOtRg15NqSy9Ys/4WsxVtnB3VPq+gcrQL+7cRMDOiUoDj4wbsVYjKPYaZ5HB7vsHzsnNvBMvkjxSjycUXmSDyv9+hAHm8ZQ/M9UDlhhSMgKXX4e0uhMFku+zW9FqoEtfwXNg+/lrECtzI=
zoo.                	86400	RRSIG	NSEC 8 1 86400 20191203035037 20191119035037 26920 . T2gtN6cjaews6S+7l4iav/OxZtTf2lOWlgOUucmrM7cgX9PvtMohfqQNHCxjGgkNURaYqoH7fu1nUSacqm0Z9EAluR/2rRGPvqvpLV+KGWzO37rBxCa+gSsoYgq8nj2OaUxF17CIuRO9/pIvJXge6Am/IHweFiCFspUJiAO4B7Y=
;; DNSSEC NSEC chain
.                   	86400	NSEC	root.net. NS SOA RRSIG NSEC DNSKEY
root.net.           	86400	NSEC	zoo-ns.net. A RRSIG NSEC
zoo-ns.net.         	86400	NSEC	zoo. A RRSIG NSEC
zoo.                	86400	NSEC	. NS DS RRSIG NSEC
;; Written 24 records
;; Time 2019-11-18 22:50:37 EST
```
Finally, paste the DS records that were saved in setting up the zoo dns server into the /var/lib/zones/root.zone file. Now restart knot server. The configuration of knot should be finished.

```
root@host6:/var/lib/knot/zones# vim root.zone
root@host6:/var/lib/knot/zones# systemctl restart knot
```

## Configure the DNS resolver to work with DNSSec
We need to modify the DNS resolver in order to make it verify the DNSSec signatures. SSH into the resolver vm, in this case 10.4.9.2. Become the root user `su`. First, get the keys from the root server.
```
root@host2:/etc/bind# dig . DNSKEY +short
256 3 8 AwEAAeNaU9QWXmdCsTd1IloFEeVCaAqwyFihyEL54iFaHq0rVA5cufpe 0O3/ib1uJzWUQIhGcTvYrSX6G6lxKjs9TFnOOBSDhTbms3P5OE9YCqk/ TeqsEGyQmpe0mjxSPMmagQkm3SMmZXgTTZgCy1jXMjXHgdA0ANh25vE0 XLAa2phZ
257 3 8 AwEAAZzXszNlsZU3XRWNXvfbIlGvfhuMMfgxIB5JfK7ZdmZyIyjTIejE rYPmOn+CAIxpnIz2CGmQ7eN1lPkoCCNUlaWZTuwBEhiTELu4z986ptbe a92g5zMqwEMOhK7DRTiMAPQUoslKyNZ7tCkR5o2sgUehakVaOW+fePDW XBGL2rr3s1iRZv95NaFWqs2Uxmo+ACR+opFsjwKSzkAdQPvhqzqtMxVR 1W702yKOQL5XPws718vKi0k31bVihc52+lMIYJvH8kRvvQONP/Bqhg3j 6lukOTTGJqPfkSN6CU83j+TXdkcNdcRu3Iyvt/hxqkudPsnj6Isbt6px VrttQxjwxiM=
```
The longer of these two keys is the KSK. We need to add this key locally to create the chain of trust. Open the `/etc/bind/named.conf.dnssec` file and append the following to the bottom (insert the needed KSK information). 
```
managed-keys {
  "." initial-key 257 3 8 "AwEAAZzXszNlsZU3XRWNXvfbIlGvfhuMMfgxIB5JfK7ZdmZyIyjTIejE rYPmOn+CAIxpnIz2CGmQ7eN1lPkoCCNUlaWZTuwBEhiTELu4z986ptbe a92g5zMqwEMOhK7DRTiMAPQUoslKyNZ7tCkR5o2sgUehakVaOW+fePDW XBGL2rr3s1iRZv95NaFWqs2Uxmo+ACR+opFsjwKSzkAdQPvhqzqtMxVR 1W702yKOQL5XPws718vKi0k31bVihc52+lMIYJvH8kRvvQONP/Bqhg3j 6lukOTTGJqPfkSN6CU83j+TXdkcNdcRu3Iyvt/hxqkudPsnj6Isbt6px VrttQxjwxiM=";
};
```
Before closing the file, we need to make one more modification. modify the dnssec-validation option to be true.
```
dnssec-validation true;
```
Save the configuration file and restart bind
```
systemctl restart bind9
```

## Verify the DNSSec configuration
Use dig to verify that you get all of the needed records.
```
cs4404@host2:~$ dig other-isp.zoo +dnssec +multi +trace

; <<>> DiG 9.10.3-P4-Ubuntu <<>> other-isp.zoo +dnssec +multi +trace
;; global options: +cmd
.                       2484 IN NS root.net.
.                       2873 IN RRSIG NS 8 0 3600 (
                                20191203034900 20191119034900 26920 .
                                gSHj+84bAYYpd9W37kI9itu1mu5g1aIPugp8tUBgm2FM
                                VWQ4MyOqSzpMLZIbuomGQ6BTr5Ld8iAnwwQVnkD4DzAL
                                LNb1X8rUSynEO1m60DYpJ7bBswu115ZOKwzFCgo6/NV+
                                h4VX5Ehbs31blpAg8k/e3Hp4IXz0wvmMv7amZzo= )
;; Received 207 bytes from 127.0.0.1#53(127.0.0.1) in 0 ms

zoo.                    3600 IN NS zoo-ns.net.
zoo.                    3600 IN DS 17164 8 1 (
                                27C38A96336331E25A55AE95854799C14129475A )
zoo.                    3600 IN DS 17164 8 2 (
                                2DD0F8F33B772336D246B98B32A56A449F2AFA20097B
                                AFF5D2EBD0DACCF27C78 )
zoo.                    3600 IN DS 17164 8 4 (
                                34E11EEF1B26F4CF988E3ABCA1271458287C4E53A36C
                                43E1ADC1C2A225BECA7A2504B872DE29A96FC85F9714
                                D82B0355 )
zoo.                    3600 IN RRSIG DS 8 1 3600 (
                                20191203035037 20191119035037 26920 .
                                dtC2frPDETNzePpyr7hCKbp+wRX7xzPOtRg15NqSy9Ys
                                /4WsxVtnB3VPq+gcrQL+7cRMDOiUoDj4wbsVYjKPYaZ5
                                HB7vsHzsnNvBMvkjxSjycUXmSDyv9+hAHm8ZQ/M9UDlh
                                hSMgKXX4e0uhMFku+zW9FqoEtfwXNg+/lrECtzI= )
;; Received 548 bytes from 10.4.9.6#53(root.net) in 0 ms

other-isp.zoo.          3600 IN A 10.4.9.4
other-isp.zoo.          3600 IN RRSIG A 8 2 3600 (
                                20191203033554 20191119033554 5308 zoo.
                                Qb09XIJFf+oa2C9T6aGIZzYgzzAUcj2pwZ/9HGIla+18
                                Zd6wCPeU7Vb2UReuJrFy3EvzrUDyMcfTVkc1Q6rl0Gd5
                                aNxAKTEyHCYD3XiTV/t3DB36g73O+ciFl3W/GgzeonaI
                                WJTs/263pGA0/amyf6pQHx9acC2WclC8dg7WKiU= )
;; Received 221 bytes from 10.4.9.5#53(zoo-ns.net) in 0 ms
```
Now use dig to verify the chain of trust. If you see the `ad` flag then it has been validated
```
root@host2:/etc/bind# dig bombast.zoo
; <<>> DiG 9.10.3-P4-Ubuntu <<>> bombast.zoo
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 61682
;; flags: qr rd ra ad; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1
;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;bombast.zoo.			IN	A
;; ANSWER SECTION:
bombast.zoo.		3600	IN	A	10.4.9.2
;; Query time: 3 msec
;; SERVER: 127.0.0.1#53(127.0.0.1)
;; WHEN: Mon Nov 18 23:13:46 EST 2019
;; MSG SIZE  rcvd: 56
```

# Appendix B: DNS attack configuration and verification
As part of the deploy scipt, the attack package is installed and configured to have no attack active. From here you can start any of the available attacks: including nxdomain, lie, nodata, drop, and iptables DoS.

## NXDOMAIN attack
SSH into the bombast DNS resolver (10.4.9.2). Start the nxdomain attack.
```
root@cs4404:~# ./select-attack nxdomain
creating symlink
```
Now, bind should be using the following zone file (The zone file used is /etc/bind/attack.db). Print the zone file and verify it looks as follows
```
root@cs4404:~# cat /etc/bind/attack.db
$TTL 60
@ IN SOA localhost. root.localhost. (2 3H 1H 1W 1H)
  IN NS  localhost.
; NXDOMAIN
other-isp.zoo   CNAME .
*.other-isp.zoo CNAME .
```
Now we can verify that the attack was successful. SSH into the client (10.4.9.1). Send a query for the other-isp.zoo domain. As you can see there was no answer to the request. indicating a nonexistant domain
```
root@cs4404:~# dig other-isp.zoo
; <<>> DiG 9.10.3-P4-Ubuntu <<>> other-isp.zoo
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 21664
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 2
;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;other-isp.zoo.			IN	A
;; ADDITIONAL SECTION:
rpz.			60	IN	SOA	localhost. root.localhost. 2 10800 3600 604800 3600
;; Query time: 1 msec
;; SERVER: 10.4.9.2#53(10.4.9.2)
;; WHEN: Tue Nov 19 16:53:46 EST 2019
;; MSG SIZE  rcvd: 95
```
However, when we query the bombast.zoo domain, we still get a response.
```
root@cs4404:~# dig bombast.zoo
; <<>> DiG 9.10.3-P4-Ubuntu <<>> bombast.zoo
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 28250
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 2
;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;bombast.zoo.			IN	A
;; ANSWER SECTION:
bombast.zoo.		3600	IN	A	10.4.9.2
;; AUTHORITY SECTION:
zoo.			3593	IN	NS	zoo-ns.net.
;; ADDITIONAL SECTION:
zoo-ns.net.		3593	IN	A	10.4.9.5
;; Query time: 3 msec
;; SERVER: 10.4.9.2#53(10.4.9.2)
;; WHEN: Tue Nov 19 16:55:55 EST 2019
;; MSG SIZE  rcvd: 96
```

## lie attack
SSH into the bombast DNS resolver (10.4.9.2). Start the lie attack.
```
root@cs4404:~# ./select-attack lie
creating symlink
```
Now SSH into the client (10.4.9.1). Query the other-isp.zoo domain. Notice that the IP address that has been sent in response is not 10.4.9.2, which is the address of the bombast.zoo server.
```
root@cs4404:~# dig other-isp.zoo
; <<>> DiG 9.10.3-P4-Ubuntu <<>> other-isp.zoo
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 28400
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 3
;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;other-isp.zoo.			IN	A
;; ANSWER SECTION:
other-isp.zoo.		5	IN	A	10.4.9.2
;; AUTHORITY SECTION:
rpz.			60	IN	NS	localhost.
;; ADDITIONAL SECTION:
localhost.		604800	IN	A	127.0.0.1
localhost.		604800	IN	AAAA	::1
;; Query time: 6 msec
;; SERVER: 10.4.9.2#53(10.4.9.2)
;; WHEN: Tue Nov 19 16:57:31 EST 2019
;; MSG SIZE  rcvd: 128
```

## nodata attack
SSH into the bombast DNS resolver (10.4.9.2). Start the nodata attack.
```
root@cs4404:~# ./select-attack nodata
creating symlink
```
Now SSH into the client (10.4.9.1). Query the other-isp.zoo domain. notice that no data is sent in response.
```
root@cs4404:~# dig other-isp.zoo
; <<>> DiG 9.10.3-P4-Ubuntu <<>> other-isp.zoo
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 55366
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 2
;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;other-isp.zoo.			IN	A
;; ADDITIONAL SECTION:
rpz.			60	IN	SOA	localhost. root.localhost. 2 10800 3600 604800 3600
;; Query time: 5 msec
;; SERVER: 10.4.9.2#53(10.4.9.2)
;; WHEN: Tue Nov 19 16:58:49 EST 2019
;; MSG SIZE  rcvd: 95
```

## drop attack
SSH into the bombast DNS resolver (10.4.9.2). Start the nodata attack.
```
root@cs4404:~# ./select-attack drop
creating symlink
```
Now SSH into the client (10.4.9.1). Query the other-isp.zoo domain. notice that the connection now times out when querying other-isp.zoo
```
root@cs4404:~# dig other-isp.zoo
; <<>> DiG 9.10.3-P4-Ubuntu <<>> other-isp.zoo
;; global options: +cmd
;; connection timed out; no servers could be reached
```

## iptable DOS attack
SSH into the bombast DNS resolver (10.4.9.2). Install the package for the iptables DOS attack
```
root@cs4404:~# dpkg -i dns-iptables-block.deb
Selecting previously unselected package dn-iptables-block.
(Reading database ... 123519 files and directories currently installed.)
Preparing to unpack dns-iptables-block.deb ...
+ /sbin/iptables -I INPUT -p udp --dport 53 -m string --hex-string '|09|other-isp|03|zoo|' --algo bm -j DROP
Unpacking dn-iptables-block (1.0-1) ...
Setting up dn-iptables-block (1.0-1) ...
```
remove any other attacks
```
root@cs4404:~# ./select-attack none
creating symlink
```
Now SSH into the client (10.4.9.1). Query the other-isp.zoo domain. Similar to the drop attack, notice that the connection now times out when querying other-isp.zoo
```
root@cs4404:~# dig other-isp.zoo
; <<>> DiG 9.10.3-P4-Ubuntu <<>> other-isp.zoo
;; global options: +cmd
;; connection timed out; no servers could be reached
```

# Appendix C: Defense configuration and verification

## Configuring the client resolver
SSH into the client VM (10.4.9.1). Install the client resolver package.  
```
root@cs4404:~# dpkg -i client-resolver.deb
Selecting previously unselected package client-dns-resolver.
(Reading database ... 123540 files and directories currently installed.)
Preparing to unpack client-resolver.deb ...
+ dpkg-divert --divert /etc/resolvconf/resolv.conf.d/head.original --rename /etc/resolvconf/resolv.conf.d/head
Adding 'diversion of /etc/resolvconf/resolv.conf.d/head to /etc/resolvconf/resolv.conf.d/head.original by client-dns-resolver'
+ dpkg-divert --divert /etc/bind/db.root.original --rename /etc/bind/db.root
Adding 'diversion of /etc/bind/db.root to /etc/bind/db.root.original by client-dns-resolver'
Unpacking client-dns-resolver (1.0-1) ...
Setting up client-dns-resolver (1.0-1) ...
```
Now, make sure the client VM is its local resolver. Open the resolver configuration file (/etc/resolv.conf) and make it look like the following. Make sure the local resolver (127.0.0.1) is above the bombast resolver (10.4.9.2) in the file.
```
root@cs4404:~# cat /etc/resolv.conf
nameserver 127.0.0.1
nameserver 10.4.9.2
```
Now, you can start any of the attacks except the iptables DoS attack (See Appendix B). Verify that this defense is working by quering the other-isp.zoo domain. We can see that even though an attack is active because we use the local resolver we are still protected.
```
root@cs4404:~# dig other-isp.zoo @127.0.0.1
; <<>> DiG 9.10.3-P4-Ubuntu <<>> other-isp.zoo @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 36131
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 2
;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;other-isp.zoo.			IN	A
;; ANSWER SECTION:
other-isp.zoo.		3600	IN	A	10.4.9.4
;; AUTHORITY SECTION:
zoo.			3582	IN	NS	zoo-ns.net.
;; ADDITIONAL SECTION:
zoo-ns.net.		3582	IN	A	10.4.9.5
;; Query time: 1 msec
;; SERVER: 127.0.0.1#53(127.0.0.1)
;; WHEN: Tue Nov 19 17:45:06 EST 2019
;; MSG SIZE  rcvd: 98
```
However, we aren't fully protected. Start the iptables DoS attack (See Appendix B). Now, query the other-isp.zoo. As you can see the traffic to other DNS servers is now blocked by the ISP, which creates a DoS for the client if they don't use the ISP's resolver.
```
root@cs4404:~# dig other-isp.zoo @127.0.0.1
; <<>> DiG 9.10.3-P4-Ubuntu <<>> other-isp.zoo @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 29864
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1
;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;other-isp.zoo.			IN	A
;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1)
;; WHEN: Tue Nov 19 18:12:15 EST 2019
;; MSG SIZE  rcvd: 42
```

# Appendix D: Manual Network and Package Configuration

## Packaging 
In order to simplify the packaging and deployment process, we utilized debian packages. 
In the `./setup` folder, each directory corresponds to the setup package for each host. 
Debian packages can specify any dependencies within the `DEBIAN/control` file. For example, the setup package for the root DNS server has a `control` file looks like this 
```
Package: root-dns-setup
Version: 1.0-1
Priority: optional
Architecture: all
Depends: knot (= 2.1.1-1build1)
Maintainer: @team9
Description: The Root DNS Server
```
The `Depends: knot (= 2.1.1-1build1)` statement ensures that `knot` is installed. 

Additionally, debian packages provide the ability to run arbitrary scripts on several hooks during the installation or removal process. We primarily utilized scripts called `preinst` (pre-install) and `postinst` (post-install) to configure networking and restart any processes respectively. The attacks (which are also debian packages) utilize `prerm` (pre-remove) so that we can enable/disable them on demand via `apt`.

Files within the debian packages are copied to their corresponding paths starting at `/` in the target system. For instance, the `root-dns-setup` package contains `var/lib/knot/zones/root.zone`. This file gets copied to `/var/lib/knot/zones/root.son` on the target system. This works well except for when you want to override the configuration for another package. The `root-dns-setup` package also contains `etc/knot/knot.conf`; however, this configuration file is owned by the `knot` package - trying to overwrite it from our setup package will fail. Luckily, `dpkg-divert` exists, which allows us to override this constraint. 
In the `preinst` hook, we can use the command `dpkg-divert --divert /etc/knot/knot.conf.original --rename /etc/knot/knot.conf` to informs `dpkg` that we want to take over control for this file. This also copies the old configuration to the path specified after `--divert`. Now we can safely overwrite configurations for other packages, which is a significant part of what we want to do!

Using debian packages ensures that our deployment is fully repeatable and idempotent.

We created a `Makefile` to automate the building of these packages. The file is mostly noise except for lines such as 
`dpkg-deb --build ./setup/root-dns ./target/setup/root-dns-setup.deb`
which actually build the packages.

## Networking 

All traffic passing in and out of the ISP's network should be going through the ISP's router. By default on the simple switched LAN, everything will go directly between the hosts so we must convince each server that they really should be sending packets to the ISP's router. Traffic between hosts outside of the ISP's network, however, should remain direct and not go through the ISP router. 

![Image description](https://www.lucidchart.com/publicSegments/view/649caaa3-5b48-4ac6-a144-bc526598e9e7/image.png)

First and foremost we must enable IP forwarding on the router. This is done on host 3 by running 
```
sysctl -w net.ipv4.ip_forward=1
```
Now packets that hit host 3 and are destined to another host will be appropriately routed instead of being swallowed into a black hole.

Now that the router has been configured to forward packets, we need to make sure hosts within the ISP network are actually using the router. This is easily accomplished by adding a specific `route`. On host 1, we can execute the following command. 
```
ip route add 10.4.9.0/24 via 10.4.9.3 dev eth0
```
This means that any traffic originating from the end client to any other host in our test network (`10.4.9.0/24`) will end up going through the ISP router. 

Let's give this a quick test.

On host 1 we having the following routes defined:
```
root@host1:~# ip route
10.0.0.0/8 dev eth0  proto kernel  scope link  src 10.4.9.1
10.4.9.0/24 via 10.4.9.3 dev eth0
```
And we can see that traffic should to host 6 for instance should properly get routed via the router on host 3.
```
root@host1:~# ip route get 10.4.9.6
10.4.9.6 via 10.4.9.3 dev eth0  src 10.4.9.1
    cache
```
We can setup `tcpdump` on the router (host 3) to verify that all the packets are actually flowing through it.
```
root@host3:~# tcpdump icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on eth0, link-type EN10MB (Ethernet), capture size 262144 bytes
```
Let's ping host 6 from host 1 and see what happens.
```
root@host1:~# ping 10.4.9.6 -c 4
PING 10.4.9.6 (10.4.9.6) 56(84) bytes of data.
From 10.4.9.3: icmp_seq=1 Redirect Host(New nexthop: 10.4.9.6)
64 bytes from 10.4.9.6: icmp_seq=1 ttl=64 time=13.8 ms
64 bytes from 10.4.9.6: icmp_seq=2 ttl=64 time=0.359 ms
...
```
We see that our traffic has been redirected directly to host 6: `Redirect Host(New nexthop: 10.4.9.6)`.
Here's what we see from our `tcpdump` on the router: 
```
12:26:34.454196 IP 10.4.9.1 > 10.4.9.6: ICMP echo request, id 6861, seq 1, length 64
12:26:34.454229 IP 10.4.9.3 > 10.4.9.1: ICMP redirect 10.4.9.6 to host 10.4.9.6, length 92
12:26:34.454257 IP 10.4.9.1 > 10.4.9.6: ICMP echo request, id 6861, seq 1, length 64
```
Note that the second request is just us resending the packet (same sequence id), but we receive no later packets. 
ICMP redirects have outsmarted our contrived networking topology and simply redirect hosts to talk directly. 
For demonstration, let's not accept any redirects, clear our route cache, and try again. 
```
root@host1:~# echo 0 | tee /proc/sys/net/ipv4/conf/*/accept_redirects
0
root@host1:~# ip route flush cache
```

```
root@host3:~# tcpdump icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on eth0, link-type EN10MB (Ethernet), capture size 262144 bytes
12:38:53.944219 IP 10.4.9.1 > 10.4.9.6: ICMP echo request, id 6947, seq 1, length 64
12:38:53.944311 IP 10.4.9.3 > 10.4.9.1: ICMP redirect 10.4.9.6 to host 10.4.9.6, length 92
12:38:53.944341 IP 10.4.9.1 > 10.4.9.6: ICMP echo request, id 6947, seq 1, length 64
12:38:54.943315 IP 10.4.9.1 > 10.4.9.6: ICMP echo request, id 6947, seq 2, length 64
12:38:54.943387 IP 10.4.9.3 > 10.4.9.1: ICMP redirect 10.4.9.6 to host 10.4.9.6, length 92
12:38:54.943417 IP 10.4.9.1 > 10.4.9.6: ICMP echo request, id 6947, seq 2, length 64
12:38:55.944763 IP 10.4.9.1 > 10.4.9.6: ICMP echo request, id 6947, seq 3, length 64
12:38:55.944837 IP 10.4.9.3 > 10.4.9.1: ICMP redirect 10.4.9.6 to host 10.4.9.6, length 92
12:38:55.944865 IP 10.4.9.1 > 10.4.9.6: ICMP echo request, id 6947, seq 3, length 64
```
Host 1 is certainly ignoring the routers redirects and all our traffic is going through the router as planned, but the redirects are a lot of noise so lets disable sending them as well. 
```
root@host3:~# echo 0 | tee /proc/sys/net/ipv4/conf/*/send_redirects
0
```
After this, things are looking good.
```
root@host3:~# tcpdump icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on eth0, link-type EN10MB (Ethernet), capture size 262144 bytes
12:40:24.029010 IP 10.4.9.1 > 10.4.9.6: ICMP echo request, id 6998, seq 1, length 64
12:40:24.029055 IP 10.4.9.1 > 10.4.9.6: ICMP echo request, id 6998, seq 1, length 64
12:40:25.029866 IP 10.4.9.1 > 10.4.9.6: ICMP echo request, id 6998, seq 2, length 64
12:40:25.029897 IP 10.4.9.1 > 10.4.9.6: ICMP echo request, id 6998, seq 2, length 64
12:40:26.029978 IP 10.4.9.1 > 10.4.9.6: ICMP echo request, id 6998, seq 3, length 64
12:40:26.030011 IP 10.4.9.1 > 10.4.9.6: ICMP echo request, id 6998, seq 3, length 64
```

Just to be safe, we disable sending and accepting ICMP redirects on every host in the network to make sure the topology stays intact.

On the external network, we don't want intra-host traffic to go through the ISP router. To accomplish this we create explicit routes for every host that within the ISP network, and let the LAN handle the rest. 
```
ip route add 10.4.9.1 via 10.4.9.3 dev eth0
ip route add 10.4.9.2 via 10.4.9.3 dev eth0
ip route add 10.4.9.3 via 10.4.9.3 dev eth0
```

All of this configuration is accomplished via the `preinst` hooks of the setup debian packages.

## Package Specifics

### Setup

#### Client

We elected to use host 1 as our simulated end user. In order to accurately simulate the infrastructure of client, we created a debian package which handles all of the necessary installations and configuration. The client package depends on only one library, `uml-utilities`, which is used by ssh during tunneling. In our `preinst` script, we `ip route add 10.4.9.0/24 via 10.4.9.2 dev eth0`, which tells the client that if it wants to reach any ip on our subnet, it needs to route it through the ISP's router which is located at `10.4.9.2`. We also disable ICMP redirects, and do another `dpkg-divert` on each file we are replacing. These files are `/etc/resolvconf/resolv.conf.d/base` and `/etc/resolvconf/interface-order`. The first file is used to append lines to the list of nameservers used by the client, so this file contains `nameserver 10.4.9.2` which points it to the proper ISP DNS resolver. The second file is empty so that resolvconf doesn't load WPI's nameserver from the DHCP server. From there, our `postinst` script runs `resolvconf -u` which reloads the resolvconf service, updating the `/etc/resolv.conf` file to point at the desired nameservers.

#### Bombast DNS Resolver

On host 3, we set up a DNS cache and resolver which is dependent upon the `bind9` package. We made several configuration changes to enable it to work in our specific network topology. Bind9 uses the `/etc/bind/named.conf.options` file for some of its configuration settings. In this file, we had to enable recursion, and specify which IPs we would allow recursion for. We elected to allow recursion from localhost (`127.0.0.1`) and any machine on our subnet (`10.4.9.0/24`). `bind9` also uses the `/etc/bind/db.root` as its zone file. We had to edit this file to point to our root DNS server, which is located on our host 6 (10.4.9.6). Finally, we had to add a line to the `/etc/resolv.conf` on our client, host 1 (`10.4.9.1`) containing `nameserver 10.4.9.3`, which lets the client know that it should route its DNS traffic through our resolver. At this point, we have a functional DNS cache and resolver which receives DNS traffic from our client.

#### VPN Host

The VPN-Host is the what our VPN client will tunnel its traffic to, preventing the ISP's router/resolver from seeing our traffic at all. Again, this package only depends on SSH, so the depends section of the control file is unnecessary. In our `postinst` script, we are enabling IP forwarding, adding our client's `id_rsa.pub` key to our `~/.ssh/authorized_keys` file so that we have root access to host 3, and then `systemctl restart sshd` to ensure that the config changes have been reflected. We also have a new `/etc/ssh/sshd_config` file reflecting two changes, `PermitTunnel yes` which allows tunneling, and `PermitRootLogin prohibit-password` which prevents clients from accessing the SSH channel with a password, mandating the presence of their public key in our `authorized_keys` file. Finally, we have a similar `/etc/network/interfaces` file which sets up the tunnel interfaces and sets up the routes and iptables automatically.

#### External Web Server

On host 4, we have set up a host representing a web server of a competing ISP (not Bombast). Again, we have created a debian package to set up all of the necessary configurations. In our `preinst` script, we run `iproute add 10.4.9.1 via 10.4.9.2 dev eth0`, which tells the host that it can reach host 1, our client, through host 2, the ISP's router. We then disable ICMP redirects for good measure. This package doesn't depend on any other packages, so the depends line in the `DEBIAN/control` file is omitted. In our `postinst` script we simply enable and start the `systemctl webserver` service, which we defined and configured in `/etc/systemd/system/web-server.service`. We have also included `/root/index.html`, which is an extremely simple webpage which this host will serve up to those that request it.

#### .zoo DNS Server

On host 5, we implemented the authoritative DNS server for the `.zoo` domain. We implemented this using the `knot (= 2.1.1-1build1)` package, and thus this is listed as a dependency in the `DEBIAN/control` file. In our `preinst` script, we run `ip route add 10.4.9.1 via 10.4.9.2 dev eth0` which again creates a route to host 1 through host 2. We then also disable ICMP redirects and run a `dpkg-divert` on `/etc/knot/knot.conf` so that the debian package will respect our new version of that file. We have also included a few files, including a configuration file for `knot` and a zones file to specify the location of other servers in the DNS hierarchy. The `/etc/knot/knot.conf` file specifies that the server should listen on port 53 as DNS servers should, where it should put its logs, and where the appropriate zone file is located. This file, which is located at `/var/lib/knot/zones/zoo.zones` contains the following:

```
zoo.           IN SOA zoo-ns.net. fake.nope.com 2019111300 1800 900 604800 86400
other-isp.zoo. IN A   10.4.9.4
bombast.zoo.   IN A   10.4.9.2
```
These entries tell the server that the domain `other-isp.zoo` is located at `10.4.9.4`, which is where we have set up our external web server. It also specifies that the Bombast web server is located at `10.4.9.2`.

#### Root DNS Server
On host 6, we have implemented our root DNS server using `knot`, and as such, `knot` has been included in the `root-dns` debian package dependencies. In our `preinst` script, we ran `ip route add 10.4.9.1 via 10.4.9.2 dev eth0`, which tells the server that the route to hist 1 is through host 2. We also disable ICMP redirects, and run a `dpkg-divert` on the `/etc/knot/knot.conf` file so that dpkg will respect our new version. That being said, in that knot configuration file we included, we simply tell the server to listen for DNS requests on the appropriate port 53, to put its logs into `syslog`, and the location of the zone file, which we include in `/var/lib/knot/zones/root.zone`. The contents of that file are as follows:

```
$TTL 1h
.                   IN SOA root.net. fake-email.doesntexit.com. 2019111300 1800 900 604800 86400
.                   IN NS  root.net.
root.net.           IN A   10.4.9.6

zoo.                IN NS  zoo-ns.net.
zoo-ns.net.         IN A   10.4.9.5
```

Above, we specify the time-to-live as 1 hour. Then we provide a fake mailserver since we don't need to be emailing any maintaners. Following that, we say that the root DNS server is located at our own IP, `10.4.9.6`, and that the nameserver for zoo.net is located at `10.4.9.5`, which is the address of our authoritative name server.

### Bombast DNS Resolver, Web Server & Router

On host 3, we set up a DNS cache and resolver which is dependent upon the `bind9` package. We made several configuration changes to enable it to work in our specific network topology. Bind9 uses the `/etc/bind/named.conf.options` file for some of its configuration settings. In this file, we had to enable recursion, and specify which IPs we would allow recursion for. We elected to allow recursion from localhost (`127.0.0.1`) and any machine on our subnet (`10.4.9.0/24`). The `bind9` package also uses the `/etc/bind/db.root` to locate the root servers. By default this points at all of the internets 900+ root servers, but we just want it to point to our root DNS server, which is located on our host 6 (`10.4.9.6`). At this point, we have a functional DNS cache and resolver which receives DNS traffic from our client.

Next, we have out `postinst` script. In here, we simply run a `systemctl restart knot` to make sure that the knot service respects the configuration changes that we've made. For cleanup, we have included a command that removes the `dpkg-divert` on the knot configuration file, which returns it to the `knot` package.

### Attack

#### DNS IPTables Block

Our IPTables attack was extremely simple to implement, as it would be for an ISP that controls the router through which all of our traffic flows. Our debian package consists of a `preinst` script that simply creates a new IPTables rule which blocks all packets containing the string `other-isp.zoo`, as a DNS request for that domain name would. The command we used to do that is `iptables -I FORWARD -p udp --dport 53 -m string --hex-string "|09|other-isp|03|zoo|" --algo bm -j DROP`. We are specifying here that we want to insert a rule to our IP tables which drops packets that are of the UDP protocol, came in on port 53, and are not destined for our own IP tables (i.e. they need to be forwarded). We then tell iptables that we want to drop any packets matching that description. Simple as that, we have blocked the client from making any DNS requests for that website. In our `prerm` script, we simply run `iptables -D INPUT -p udp --dport 53 -m string --hex-string "|09|other-isp|03|zoo|" --algo bm -j DROP`, which removes that rule from iptables, allowing that traffic again.

### Defense

#### DNSSec

We have implemented two different debian packages for our DNSSec defense, `root-dnssec` and `zoo-dnssec`. These have been documented in our demonstration, Appendix A, and the Defense section.

#### VPN-Client

In order to implement our defense against denial of service attacks from our ISP, we set up a VPN connection through host 3 for our client to connect to. This was implemented in another debian package. The client package only depends on SSH, which comes natively with ubuntu 16.04, so the depends section of the control file has been removed entirely. Our `postinst` script simply enables IPv4 forwarding for good measure. Additionally, we have included an `id_rsa` file and an `id_rsa.pub` file to be used as our ssh keys for connection. These have been placed in the appropriate `/root/.ssh/` directory. Then we have included a new `/etc/network/interfaces` file which defines several IP and interface routes, as well as defining a command to setup the tunnel interface. This allows us to run `ifup tun0` on both the host and the client after package installation to setup the VPN.

Note: there is a bit of a race condition in setting up the host and client, so it is advised to wait a few seconds in between running on host 1 and on host 3, as in the following:

```
#on 1 
ifup tun0 &
sleep 5
#on 3 
ifup tun0
```


## Deployment 

Deploying the debian packages is quite simple once they are created. We `rsync` each `*-setup.deb` onto the appropriate host and then run `apt-get install --assume-yes --fix-broken ./*-setup.deb`. The `--fix-broken` option tells `apt-get` to download any missing `Deps` specified in the `control` file. The attacks are deployed in exactly the same way. 

When a fresh VM boots, it initiates unattended upgrades which hold the dpkg lock for an extended period of time. In order to circumvent this we disable them and reboot the machines. 

In the beginning of the mission, the VMs frequently ran out of memory while installing the packages, resulting in broken states. We create swap space automatically on the VMs to avoid this.

This process is fully scripted in `./deploy`.


# Appendix E: Automated Attack Demo Output 
<div style="background-color:#404040" class="full-width">
<pre>
<span>SKIP_PAUSE=1 ./demo_attack</span>
Verifying passwordless ssh for root@10.4.9.[1-6]
</span><span style="color:lime;">host 1 good</span>
<span style="color:lime;">host 2 good</span>
<span style="color:lime;">host 3 good</span>
<span style="color:lime;">host 4 good</span>
<span style="color:lime;">host 5 good</span>
<span style="color:lime;">host 6 good</span>

████████╗███████╗ █████╗ ███╗   ███╗     █████╗ 
╚══██╔══╝██╔════╝██╔══██╗████╗ ████║    ██╔══██╗
   ██║   █████╗  ███████║██╔████╔██║    ╚██████║
   ██║   ██╔══╝  ██╔══██║██║╚██╔╝██║     ╚═══██║
   ██║   ███████╗██║  ██║██║ ╚═╝ ██║     █████╔╝
   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝     ╚════╝ 
                                                
      ██████╗ ███████╗███╗   ███╗ ██████╗       
      ██╔══██╗██╔════╝████╗ ████║██╔═══██╗      
█████╗██║  ██║█████╗  ██╔████╔██║██║   ██║█████╗
╚════╝██║  ██║██╔══╝  ██║╚██╔╝██║██║   ██║╚════╝
      ██████╔╝███████╗██║ ╚═╝ ██║╚██████╔╝      
      ╚═════╝ ╚══════╝╚═╝     ╚═╝ ╚═════╝       


██████╗ ██████╗ ███████╗
██╔══██╗██╔══██╗╚══███╔╝
██████╔╝██████╔╝  ███╔╝ 
██╔══██╗██╔═══╝  ███╔╝  
██║  ██║██║     ███████╗
╚═╝  ╚═╝╚═╝     ╚══════╝
<span style="color:yellow;"> ------------------------------------------------------------------------------
|                                                                              |
| </span><span style="color:#a9a9fc;">This attack utilizes the Response Policy Zones (RPZ) feature of Bind 9 to   </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">rewrite DNS responses. We have deployed several RPZ zone files into         </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">/etc/bind, each illustrating a different mode of attack. To switch between  </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">different attack modes, we create and alter symlinks to /etc/bind/attack.db </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">and restart the bind9 service. We will now show all of the attacks and what </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">happens from the clients perspective by running dig on the targeted domain  </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">(other-isp.zoo) and a non-targeted domain (bombast.zoo).                    </span><span style="color:yellow;"> |
|                                                                              |
------------------------------------------------------------------------------
</span><span style="color:lime;"></span><span style="font-weight:bold;color:lime;">HOST 2: executing </span><span style="text-decoration:underline;font-weight:bold;color:lime;">/root/select-attack 2&gt;&amp;1 | grep usage</span><span style="font-weight:bold;color:lime;"></span>
<span style="color:lime;">usage: select-attack [-h] {lie,none,nodata,drop,nxdomain}</span>
<span style="color:yellow;"> ---------------------------------------------------------------------------
|                                                                           |
| </span><span style="color:#a9a9fc;">First let's show what it looks like when there's no attack running. This </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">corresponds to an empty RPZ zone file.                                   </span><span style="color:yellow;"> |
|                                                                           |
---------------------------------------------------------------------------
</span><span style="color:lime;"></span><span style="font-weight:bold;color:lime;">HOST 2: executing </span><span style="text-decoration:underline;font-weight:bold;color:lime;">/root/select-attack none</span><span style="font-weight:bold;color:lime;"></span>
<span style="color:lime;">creating symlink</span>
<span style="color:lime;"></span><span style="font-weight:bold;color:lime;">HOST 2: executing </span><span style="text-decoration:underline;font-weight:bold;color:lime;">cat /etc/bind/attack.db</span><span style="font-weight:bold;color:lime;"></span>
<span style="color:lime;">$TTL 60</span>
<span style="color:lime;">@ IN SOA localhost. root.localhost. (2 3H 1H 1W 1H)</span>
<span style="color:lime;">IN NS  localhost.</span>
<span style="color:lime;"></span>
<span style="color:yellow;"> ----------------------------------------------------------------------------
|                                                                            |
| </span><span style="color:#a9a9fc;">Bind doesn't like completely empty RPZ zone files, so we give it one that </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">does nothing.                                                             </span><span style="color:yellow;"> |
|                                                                            |
----------------------------------------------------------------------------
</span><span style="color:#ff6e6e;"></span><span style="font-weight:bold;color:#ff6e6e;">HOST 1: executing </span><span style="text-decoration:underline;font-weight:bold;color:#ff6e6e;">dig bombast.zoo</span><span style="font-weight:bold;color:#ff6e6e;"></span>
<span style="color:#ff6e6e;"></span>
<span style="color:#ff6e6e;">; &lt;&lt;&gt;&gt; DiG 9.10.3-P4-Ubuntu &lt;&lt;&gt;&gt; bombast.zoo</span>
<span style="color:#ff6e6e;">;; global options: +cmd</span>
<span style="color:#ff6e6e;">;; Got answer:</span>
<span style="color:#ff6e6e;">;; -&gt;&gt;HEADER&lt;&lt;- opcode: QUERY, status: NOERROR, id: 51314</span>
<span style="color:#ff6e6e;">;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 2</span>
<span style="color:#ff6e6e;"></span>
<span style="color:#ff6e6e;">;; OPT PSEUDOSECTION:</span>
<span style="color:#ff6e6e;">; EDNS: version: 0, flags:; udp: 4096</span>
<span style="color:#ff6e6e;">;; QUESTION SECTION:</span>
<span style="color:#ff6e6e;">;bombast.zoo.			IN	A</span>
<span style="color:#ff6e6e;"></span>
<span style="color:#ff6e6e;">;; ANSWER SECTION:</span>
<span style="color:#ff6e6e;">bombast.zoo.		3600	IN	A	10.4.9.2</span>
<span style="color:#ff6e6e;"></span>
<span style="color:#ff6e6e;">;; AUTHORITY SECTION:</span>
<span style="color:#ff6e6e;">zoo.			3600	IN	NS	zoo-ns.net.</span>
<span style="color:#ff6e6e;"></span>
<span style="color:#ff6e6e;">;; ADDITIONAL SECTION:</span>
<span style="color:#ff6e6e;">zoo-ns.net.		3600	IN	A	10.4.9.5</span>
<span style="color:#ff6e6e;"></span>
<span style="color:#ff6e6e;">;; Query time: 3 msec</span>
<span style="color:#ff6e6e;">;; SERVER: 10.4.9.2#53(10.4.9.2)</span>
<span style="color:#ff6e6e;">;; WHEN: Wed Nov 20 21:00:45 EST 2019</span>
<span style="color:#ff6e6e;">;; MSG SIZE  rcvd: 96</span>
<span style="color:#ff6e6e;"></span>
<span style="color:#ff6e6e;"></span><span style="font-weight:bold;color:#ff6e6e;">HOST 1: executing </span><span style="text-decoration:underline;font-weight:bold;color:#ff6e6e;">dig other-isp.zoo</span><span style="font-weight:bold;color:#ff6e6e;"></span>
<span style="color:#ff6e6e;"></span>
<span style="color:#ff6e6e;">; &lt;&lt;&gt;&gt; DiG 9.10.3-P4-Ubuntu &lt;&lt;&gt;&gt; other-isp.zoo</span>
<span style="color:#ff6e6e;">;; global options: +cmd</span>
<span style="color:#ff6e6e;">;; Got answer:</span>
<span style="color:#ff6e6e;">;; -&gt;&gt;HEADER&lt;&lt;- opcode: QUERY, status: NOERROR, id: 14526</span>
<span style="color:#ff6e6e;">;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 2</span>
<span style="color:#ff6e6e;"></span>
<span style="color:#ff6e6e;">;; OPT PSEUDOSECTION:</span>
<span style="color:#ff6e6e;">; EDNS: version: 0, flags:; udp: 4096</span>
<span style="color:#ff6e6e;">;; QUESTION SECTION:</span>
<span style="color:#ff6e6e;">;other-isp.zoo.			IN	A</span>
<span style="color:#ff6e6e;"></span>
<span style="color:#ff6e6e;">;; ANSWER SECTION:</span>
<span style="color:#ff6e6e;">other-isp.zoo.		3600	IN	A	10.4.9.4</span>
<span style="color:#ff6e6e;"></span>
<span style="color:#ff6e6e;">;; AUTHORITY SECTION:</span>
<span style="color:#ff6e6e;">zoo.			3599	IN	NS	zoo-ns.net.</span>
<span style="color:#ff6e6e;"></span>
<span style="color:#ff6e6e;">;; ADDITIONAL SECTION:</span>
<span style="color:#ff6e6e;">zoo-ns.net.		3599	IN	A	10.4.9.5</span>
<span style="color:#ff6e6e;"></span>
<span style="color:#ff6e6e;">;; Query time: 3 msec</span>
<span style="color:#ff6e6e;">;; SERVER: 10.4.9.2#53(10.4.9.2)</span>
<span style="color:#ff6e6e;">;; WHEN: Wed Nov 20 21:00:46 EST 2019</span>
<span style="color:#ff6e6e;">;; MSG SIZE  rcvd: 98</span>
<span style="color:#ff6e6e;"></span>
<span style="color:yellow;"> -----------------------------------------------------------------------------
|                                                                             |
| </span><span style="color:#a9a9fc;">This is what the output should like for unaltered requests and responses.  </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">We have the correct IP addresses for both servers. Let's curl just to make </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">sure.                                                                      </span><span style="color:yellow;"> |
|                                                                             |
-----------------------------------------------------------------------------
</span><span style="color:#ff6e6e;"></span><span style="font-weight:bold;color:#ff6e6e;">HOST 1: executing </span><span style="text-decoration:underline;font-weight:bold;color:#ff6e6e;">curl -s bombast.zoo   2&gt;&amp;1</span><span style="font-weight:bold;color:#ff6e6e;"></span>
<span style="color:#ff6e6e;">Connected to BombastISP server at 10.4.9.2</span>
<span style="color:#ff6e6e;"></span>
<span style="color:#ff6e6e;"></span><span style="font-weight:bold;color:#ff6e6e;">HOST 1: executing </span><span style="text-decoration:underline;font-weight:bold;color:#ff6e6e;">curl -s other-isp.zoo 2&gt;&amp;1</span><span style="font-weight:bold;color:#ff6e6e;"></span>
<span style="color:#ff6e6e;">Connected to OtherISP server at 10.4.9.4</span>
<span style="color:#ff6e6e;"></span>
<span style="color:yellow;"> ---------------------------------------------------------------------------
|                                                                           |
| </span><span style="color:#a9a9fc;">If the ISP wishes to give clients an NXDOMAIN for other-isp.zoo (and all </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">its subdomains), we merely have to add the appropriate record to the RPZ </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">zone file.                                                               </span><span style="color:yellow;"> |
|                                                                           |
---------------------------------------------------------------------------
</span><span style="color:lime;"></span><span style="font-weight:bold;color:lime;">HOST 2: executing </span><span style="text-decoration:underline;font-weight:bold;color:lime;">/root/select-attack nxdomain</span><span style="font-weight:bold;color:lime;"></span>
<span style="color:lime;">creating symlink</span>
<span style="color:lime;"></span><span style="font-weight:bold;color:lime;">HOST 2: executing </span><span style="text-decoration:underline;font-weight:bold;color:lime;">cat /etc/bind/attack.db</span><span style="font-weight:bold;color:lime;"></span>
<span style="color:lime;">$TTL 60</span>
<span style="color:lime;">@ IN SOA localhost. root.localhost. (2 3H 1H 1W 1H)</span>
<span style="color:lime;">IN NS  localhost.</span>
<span style="color:lime;"></span>
<span style="color:lime;">; NXDOMAIN</span>
<span style="color:lime;">other-isp.zoo   CNAME .</span>
<span style="color:lime;">*.other-isp.zoo CNAME .</span>
<span style="color:yellow;"> ------------------------------------------------------------------------------
|                                                                              |
| </span><span style="color:#a9a9fc;">The RPZ format uses special codes to decide what to do with a given domain. </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">The &quot;.&quot; here means to return NXDOMAIN. Let's see what happens when we run   </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">dig now.                                                                    </span><span style="color:yellow;"> |
|                                                                              |
------------------------------------------------------------------------------
</span><span style="color:#ff6e6e;"></span><span style="font-weight:bold;color:#ff6e6e;">HOST 1: executing </span><span style="text-decoration:underline;font-weight:bold;color:#ff6e6e;">dig bombast.zoo</span><span style="font-weight:bold;color:#ff6e6e;"></span>
<span style="color:#ff6e6e;"></span>
<span style="color:#ff6e6e;">; &lt;&lt;&gt;&gt; DiG 9.10.3-P4-Ubuntu &lt;&lt;&gt;&gt; bombast.zoo</span>
<span style="color:#ff6e6e;">;; global options: +cmd</span>
<span style="color:#ff6e6e;">;; Got answer:</span>
<span style="color:#ff6e6e;">;; -&gt;&gt;HEADER&lt;&lt;- opcode: QUERY, status: NOERROR, id: 8864</span>
<span style="color:#ff6e6e;">;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 2</span>
<span style="color:#ff6e6e;"></span>
<span style="color:#ff6e6e;">;; OPT PSEUDOSECTION:</span>
<span style="color:#ff6e6e;">; EDNS: version: 0, flags:; udp: 4096</span>
<span style="color:#ff6e6e;">;; QUESTION SECTION:</span>
<span style="color:#ff6e6e;">;bombast.zoo.			IN	A</span>
<span style="color:#ff6e6e;"></span>
<span style="color:#ff6e6e;">;; ANSWER SECTION:</span>
<span style="color:#ff6e6e;">bombast.zoo.		3600	IN	A	10.4.9.2</span>
<span style="color:#ff6e6e;"></span>
<span style="color:#ff6e6e;">;; AUTHORITY SECTION:</span>
<span style="color:#ff6e6e;">zoo.			3600	IN	NS	zoo-ns.net.</span>
<span style="color:#ff6e6e;"></span>
<span style="color:#ff6e6e;">;; ADDITIONAL SECTION:</span>
<span style="color:#ff6e6e;">zoo-ns.net.		3600	IN	A	10.4.9.5</span>
<span style="color:#ff6e6e;"></span>
<span style="color:#ff6e6e;">;; Query time: 6 msec</span>
<span style="color:#ff6e6e;">;; SERVER: 10.4.9.2#53(10.4.9.2)</span>
<span style="color:#ff6e6e;">;; WHEN: Wed Nov 20 21:00:51 EST 2019</span>
<span style="color:#ff6e6e;">;; MSG SIZE  rcvd: 96</span>
<span style="color:#ff6e6e;"></span>
<span style="color:yellow;"> ------------------------------------------------------------------------------
|                                                                              |
| </span><span style="color:#a9a9fc;">This looks exactly the same as it did before (which is good) because it was </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">not targeted in the RPZ file.                                               </span><span style="color:yellow;"> |
|                                                                              |
------------------------------------------------------------------------------
</span><span style="color:#ff6e6e;"></span><span style="font-weight:bold;color:#ff6e6e;">HOST 1: executing </span><span style="text-decoration:underline;font-weight:bold;color:#ff6e6e;">dig other-isp.zoo</span><span style="font-weight:bold;color:#ff6e6e;"></span>
<span style="color:#ff6e6e;"></span>
<span style="color:#ff6e6e;">; &lt;&lt;&gt;&gt; DiG 9.10.3-P4-Ubuntu &lt;&lt;&gt;&gt; other-isp.zoo</span>
<span style="color:#ff6e6e;">;; global options: +cmd</span>
<span style="color:#ff6e6e;">;; Got answer:</span>
<span style="color:#ff6e6e;">;; -&gt;&gt;HEADER&lt;&lt;- opcode: QUERY, status: NXDOMAIN, id: 33567</span>
<span style="color:#ff6e6e;">;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 2</span>
<span style="color:#ff6e6e;"></span>
<span style="color:#ff6e6e;">;; OPT PSEUDOSECTION:</span>
<span style="color:#ff6e6e;">; EDNS: version: 0, flags:; udp: 4096</span>
<span style="color:#ff6e6e;">;; QUESTION SECTION:</span>
<span style="color:#ff6e6e;">;other-isp.zoo.			IN	A</span>
<span style="color:#ff6e6e;"></span>
<span style="color:#ff6e6e;">;; ADDITIONAL SECTION:</span>
<span style="color:#ff6e6e;">rpz.			60	IN	SOA	localhost. root.localhost. 2 10800 3600 604800 3600</span>
<span style="color:#ff6e6e;"></span>
<span style="color:#ff6e6e;">;; Query time: 2 msec</span>
<span style="color:#ff6e6e;">;; SERVER: 10.4.9.2#53(10.4.9.2)</span>
<span style="color:#ff6e6e;">;; WHEN: Wed Nov 20 21:00:52 EST 2019</span>
<span style="color:#ff6e6e;">;; MSG SIZE  rcvd: 95</span>
<span style="color:#ff6e6e;"></span>
<span style="color:yellow;"> ---------------------------------------------------------------------------
|                                                                           |
| </span><span style="color:#a9a9fc;">Instead of getting the correct address this time, we see we have a       </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">NXDOMAIN!                                                                </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">    ;; -&gt;&gt;HEADER&lt;&lt;- opcode: QUERY, status: NXDOMAIN                      </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">This means our attack worked as expected. Looking in the ADDITIONAL      </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">SECTION, we can see that the reported authoritative server came from our </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">RPZ config.                                                              </span><span style="color:yellow;"> |
|                                                                           |
---------------------------------------------------------------------------
</span><span style="color:yellow;"> ----------------------------------------------------------------------------
|                                                                            |
| </span><span style="color:#a9a9fc;">There are several different actions we can take besides NXDOMAIN for a    </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">given RPZ trigger:                                                        </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">    NODATA: Returns an empty response (as opposed to NXDOMAIN)            </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">    DROP: drops the request and doesn't respond, usually causing a timeout</span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">    TCP-ONLY: forces the client to make a request over TCP instead of UDP.</span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">              This is useful to combat DDOS attacks because it increases  </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">              the overhead for each connection, and can be specified on a </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">              per-domain basis.                                           </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">Additionally, there's no reason we cannot just return forged responses in </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">the RPZ zone file. We refer to this as a 'lie' attack, and it is          </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">essentially equivalent to a DNS poisining attack.                         </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">We don't use TCP-ONLY, because we aren't testing DOS scenarios, but let's </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">walk through the NODATA, LIE and DROP attacks.                            </span><span style="color:yellow;"> |
|                                                                            |
----------------------------------------------------------------------------
</span><span style="color:lime;"></span><span style="font-weight:bold;color:lime;">HOST 2: executing </span><span style="text-decoration:underline;font-weight:bold;color:lime;">/root/select-attack nodata</span><span style="font-weight:bold;color:lime;"></span>
<span style="color:lime;">creating symlink</span>
<span style="color:lime;"></span><span style="font-weight:bold;color:lime;">HOST 2: executing </span><span style="text-decoration:underline;font-weight:bold;color:lime;">cat /etc/bind/attack.db</span><span style="font-weight:bold;color:lime;"></span>
<span style="color:lime;">$TTL 60</span>
<span style="color:lime;">@ IN SOA localhost. root.localhost. (2 3H 1H 1W 1H)</span>
<span style="color:lime;">IN NS  localhost.</span>
<span style="color:lime;"></span>
<span style="color:lime;">; NODATA  returns empty response</span>
<span style="color:lime;">other-isp.zoo   CNAME *.</span>
<span style="color:yellow;"> -----------------------------------------------------------------------------
|                                                                             |
| </span><span style="color:#a9a9fc;">Here &quot;*.&quot; means NODATA. Let's look at the dig output. From here forward we </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">omit the dig output of bombast.zoo because it doesn't change.              </span><span style="color:yellow;"> |
|                                                                             |
-----------------------------------------------------------------------------
</span><span style="color:#ff6e6e;"></span><span style="font-weight:bold;color:#ff6e6e;">HOST 1: executing </span><span style="text-decoration:underline;font-weight:bold;color:#ff6e6e;">dig other-isp.zoo</span><span style="font-weight:bold;color:#ff6e6e;"></span>
<span style="color:#ff6e6e;"></span>
<span style="color:#ff6e6e;">; &lt;&lt;&gt;&gt; DiG 9.10.3-P4-Ubuntu &lt;&lt;&gt;&gt; other-isp.zoo</span>
<span style="color:#ff6e6e;">;; global options: +cmd</span>
<span style="color:#ff6e6e;">;; Got answer:</span>
<span style="color:#ff6e6e;">;; -&gt;&gt;HEADER&lt;&lt;- opcode: QUERY, status: NOERROR, id: 38807</span>
<span style="color:#ff6e6e;">;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 2</span>
<span style="color:#ff6e6e;"></span>
<span style="color:#ff6e6e;">;; OPT PSEUDOSECTION:</span>
<span style="color:#ff6e6e;">; EDNS: version: 0, flags:; udp: 4096</span>
<span style="color:#ff6e6e;">;; QUESTION SECTION:</span>
<span style="color:#ff6e6e;">;other-isp.zoo.			IN	A</span>
<span style="color:#ff6e6e;"></span>
<span style="color:#ff6e6e;">;; ADDITIONAL SECTION:</span>
<span style="color:#ff6e6e;">rpz.			60	IN	SOA	localhost. root.localhost. 2 10800 3600 604800 3600</span>
<span style="color:#ff6e6e;"></span>
<span style="color:#ff6e6e;">;; Query time: 3 msec</span>
<span style="color:#ff6e6e;">;; SERVER: 10.4.9.2#53(10.4.9.2)</span>
<span style="color:#ff6e6e;">;; WHEN: Wed Nov 20 21:00:56 EST 2019</span>
<span style="color:#ff6e6e;">;; MSG SIZE  rcvd: 95</span>
<span style="color:#ff6e6e;"></span>
<span style="color:yellow;"> ----------------------------------------------------------------------------
|                                                                            |
| </span><span style="color:#a9a9fc;">This time, our status just says NOERROR and we get no A record back.      </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">    ;; -&gt;&gt;HEADER&lt;&lt;- opcode: QUERY, status: NOERROR                        </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">Oddly, bind still gives us the SOA record in the ADDITIONAL SECTION. This </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">is weird because it's definitely not NODATA, maybe it should be called    </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">SOMEDATA.                                                                 </span><span style="color:yellow;"> |
|                                                                            |
----------------------------------------------------------------------------
</span><span style="color:lime;"></span><span style="font-weight:bold;color:lime;">HOST 2: executing </span><span style="text-decoration:underline;font-weight:bold;color:lime;">/root/select-attack lie</span><span style="font-weight:bold;color:lime;"></span>
<span style="color:lime;">creating symlink</span>
<span style="color:lime;"></span><span style="font-weight:bold;color:lime;">HOST 2: executing </span><span style="text-decoration:underline;font-weight:bold;color:lime;">cat /etc/bind/attack.db</span><span style="font-weight:bold;color:lime;"></span>
<span style="color:lime;">$TTL 60</span>
<span style="color:lime;">@ IN SOA localhost. root.localhost. (2 3H 1H 1W 1H)</span>
<span style="color:lime;">IN NS  localhost.</span>
<span style="color:lime;"></span>
<span style="color:lime;">; LIE give a straight up wrong address</span>
<span style="color:lime;">other-isp.zoo   A 10.4.9.2</span>
<span style="color:lime;">*.other-isp.zoo A 10.4.9.2</span>
<span style="color:yellow;"> ------------------------------------------------------------------------------
|                                                                              |
| </span><span style="color:#a9a9fc;">Instead of putting weird codes for things like NXDOMAIN or NODATA, we can   </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">put real records too! Here we are returning the IP address of our server    </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">instead of the real IP. This is quite a sinister thing to do as anybody     </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">that wants to look at other ISP websites would simply be redirected to ours </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">instead.                                                                    </span><span style="color:yellow;"> |
|                                                                              |
------------------------------------------------------------------------------
</span><span style="color:#ff6e6e;"></span><span style="font-weight:bold;color:#ff6e6e;">HOST 1: executing </span><span style="text-decoration:underline;font-weight:bold;color:#ff6e6e;">dig other-isp.zoo</span><span style="font-weight:bold;color:#ff6e6e;"></span>
<span style="color:#ff6e6e;"></span>
<span style="color:#ff6e6e;">; &lt;&lt;&gt;&gt; DiG 9.10.3-P4-Ubuntu &lt;&lt;&gt;&gt; other-isp.zoo</span>
<span style="color:#ff6e6e;">;; global options: +cmd</span>
<span style="color:#ff6e6e;">;; Got answer:</span>
<span style="color:#ff6e6e;">;; -&gt;&gt;HEADER&lt;&lt;- opcode: QUERY, status: NOERROR, id: 31160</span>
<span style="color:#ff6e6e;">;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 3</span>
<span style="color:#ff6e6e;"></span>
<span style="color:#ff6e6e;">;; OPT PSEUDOSECTION:</span>
<span style="color:#ff6e6e;">; EDNS: version: 0, flags:; udp: 4096</span>
<span style="color:#ff6e6e;">;; QUESTION SECTION:</span>
<span style="color:#ff6e6e;">;other-isp.zoo.			IN	A</span>
<span style="color:#ff6e6e;"></span>
<span style="color:#ff6e6e;">;; ANSWER SECTION:</span>
<span style="color:#ff6e6e;">other-isp.zoo.		5	IN	A	10.4.9.2</span>
<span style="color:#ff6e6e;"></span>
<span style="color:#ff6e6e;">;; AUTHORITY SECTION:</span>
<span style="color:#ff6e6e;">rpz.			60	IN	NS	localhost.</span>
<span style="color:#ff6e6e;"></span>
<span style="color:#ff6e6e;">;; ADDITIONAL SECTION:</span>
<span style="color:#ff6e6e;">localhost.		604800	IN	A	127.0.0.1</span>
<span style="color:#ff6e6e;">localhost.		604800	IN	AAAA	::1</span>
<span style="color:#ff6e6e;"></span>
<span style="color:#ff6e6e;">;; Query time: 5 msec</span>
<span style="color:#ff6e6e;">;; SERVER: 10.4.9.2#53(10.4.9.2)</span>
<span style="color:#ff6e6e;">;; WHEN: Wed Nov 20 21:00:59 EST 2019</span>
<span style="color:#ff6e6e;">;; MSG SIZE  rcvd: 128</span>
<span style="color:#ff6e6e;"></span>
<span style="color:yellow;"> ----------------------------------------------------------------------------
|                                                                            |
| </span><span style="color:#a9a9fc;">Looking at the ANSWER SECTION, we see that we now have the wrong address. </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">    other-isp.zoo.    5   IN  A   10.4.9.2                                </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">If we curl other-isp.zoo, it will think everything is working and give us </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">the wrong web page without complaint.                                     </span><span style="color:yellow;"> |
|                                                                            |
----------------------------------------------------------------------------
</span><span style="color:#ff6e6e;"></span><span style="font-weight:bold;color:#ff6e6e;">HOST 1: executing </span><span style="text-decoration:underline;font-weight:bold;color:#ff6e6e;">curl -s other-isp.zoo</span><span style="font-weight:bold;color:#ff6e6e;"></span>
<span style="color:#ff6e6e;">Connected to BombastISP server at 10.4.9.2</span>
<span style="color:#ff6e6e;"></span>
<span style="color:lime;"></span><span style="font-weight:bold;color:lime;">HOST 2: executing </span><span style="text-decoration:underline;font-weight:bold;color:lime;">/root/select-attack drop</span><span style="font-weight:bold;color:lime;"></span>
<span style="color:lime;">creating symlink</span>
<span style="color:lime;"></span><span style="font-weight:bold;color:lime;">HOST 2: executing </span><span style="text-decoration:underline;font-weight:bold;color:lime;">cat /etc/bind/attack.db</span><span style="font-weight:bold;color:lime;"></span>
<span style="color:lime;">$TTL 60</span>
<span style="color:lime;">@ IN SOA localhost. root.localhost. (2 3H 1H 1W 1H)</span>
<span style="color:lime;">IN NS  localhost.</span>
<span style="color:lime;"></span>
<span style="color:lime;">; DROP  results in timeout from client</span>
<span style="color:lime;">other-isp.zoo   CNAME rpz-drop.</span>
<span style="color:lime;">*.other-isp.zoo CNAME rpz-drop.</span>
<span style="color:yellow;"> -----------------------------------------------------------------------------
|                                                                             |
| </span><span style="color:#a9a9fc;">If the ISP wants to make people trying to load other ISP's websites to see </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">some spinners in their browser, the could instead DROP the requests.       </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">We can use the special code &quot;.rpz-drop&quot; to do this. By default dig does a  </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">few retries, let's limit it to one and pull back the timeout so we aren't  </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">sitting here forever.                                                      </span><span style="color:yellow;"> |
|                                                                             |
-----------------------------------------------------------------------------
</span><span style="color:#ff6e6e;"></span><span style="font-weight:bold;color:#ff6e6e;">HOST 1: executing </span><span style="text-decoration:underline;font-weight:bold;color:#ff6e6e;">dig other-isp.zoo +tries=1 +time=3</span><span style="font-weight:bold;color:#ff6e6e;"></span>
<span style="color:#ff6e6e;"></span>
<span style="color:#ff6e6e;">; &lt;&lt;&gt;&gt; DiG 9.10.3-P4-Ubuntu &lt;&lt;&gt;&gt; other-isp.zoo +tries=1 +time=3</span>
<span style="color:#ff6e6e;">;; global options: +cmd</span>
<span style="color:#ff6e6e;">;; connection timed out; no servers could be reached</span>
<span style="color:yellow;"> ----------------------------------------------------------------------------
|                                                                            |
| </span><span style="color:#a9a9fc;">    ;; connection timed out; no servers could be reached                  </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">Dig thinks it couldn't reach the server, but in this case the server just </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">didn't want to talk back.                                                 </span><span style="color:yellow;"> |
|                                                                            |
----------------------------------------------------------------------------
</span><span style="color:yellow;"> -----------------------------------------------------------------------------
|                                                                             |
| </span><span style="color:#a9a9fc;">In these examples, we've only created RPZ rules that are based on domain   </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">names; however, it is possible to create rules based on other criteria. We </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">can chose to create a rule triggering from any of the following sources:   </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">    - Domain Name                                                          </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">    - IP Address/Subnet                                                    </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">    - Client IP Address/Subnet                                             </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">    - Nameserver Domain/Address/Subnet                                     </span><span style="color:yellow;"> |
|                                                                             |
-----------------------------------------------------------------------------
</span>
██████╗ ███╗   ██╗███████╗███████╗███████╗ ██████╗
██╔══██╗████╗  ██║██╔════╝██╔════╝██╔════╝██╔════╝
██║  ██║██╔██╗ ██║███████╗███████╗█████╗  ██║     
██║  ██║██║╚██╗██║╚════██║╚════██║██╔══╝  ██║     
██████╔╝██║ ╚████║███████║███████║███████╗╚██████╗
╚═════╝ ╚═╝  ╚═══╝╚══════╝╚══════╝╚══════╝ ╚═════╝

<span style="color:yellow;"> -----------------------------------------------------------------------------
|                                                                             |
| </span><span style="color:#a9a9fc;">With more effort the ISP could've designed its RPZ records to make the LIE </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">and NXDOMAIN attacks indistinguishable from a real authoritative response. </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">They would merely have to adjust the SOA record to be more convincing. As  </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">an end client this thought is pretty scary, but there is hope. We have     </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">DNSSEC now.                                                                </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">Let's get that setup.                                                      </span><span style="color:yellow;"> |
|                                                                             |
-----------------------------------------------------------------------------
</span><span style="color:aqua;"></span><span style="font-weight:bold;color:aqua;">HOST 6: executing </span><span style="text-decoration:underline;font-weight:bold;color:aqua;">dpkg --remove root-dns-setup</span><span style="font-weight:bold;color:aqua;"></span>
<span style="color:aqua;">(Reading database ... 123500 files and directories currently installed.)</span>
<span style="color:aqua;">Removing root-dns-setup (1.0-1) ...</span>
<span style="color:aqua;">+ dpkg-divert --remove /etc/knot/knot.conf</span>
<span style="color:aqua;">Removing 'diversion of /etc/knot/knot.conf to /etc/knot/knot.conf.original by root-dns-setup'</span>
<span style="color:aqua;"></span><span style="font-weight:bold;color:aqua;">HOST 6: executing </span><span style="text-decoration:underline;font-weight:bold;color:aqua;">dpkg --install root-dnssec.deb</span><span style="font-weight:bold;color:aqua;"></span>
<span style="color:aqua;">Selecting previously unselected package root-dns-dnssec.</span>
<span style="color:aqua;">(Reading database ... 123497 files and directories currently installed.)</span>
<span style="color:aqua;">Preparing to unpack root-dnssec.deb ...</span>
<span style="color:aqua;">+ dpkg-divert --divert /etc/knot/knot.conf.no-dnssec --rename /etc/knot/knot.conf</span>
<span style="color:aqua;">Adding 'diversion of /etc/knot/knot.conf to /etc/knot/knot.conf.no-dnssec by root-dns-dnssec'</span>
<span style="color:aqua;">Unpacking root-dns-dnssec (1.0-1) ...</span>
<span style="color:aqua;">Setting up root-dns-dnssec (1.0-1) ...</span>
<span style="color:aqua;">+ knotc reload</span>
<span style="color:aqua;"></span>
<span style="color:fuchsia;"></span><span style="font-weight:bold;color:fuchsia;">HOST 5: executing </span><span style="text-decoration:underline;font-weight:bold;color:fuchsia;">dpkg --remove zoo-dns-setup</span><span style="font-weight:bold;color:fuchsia;"></span>
<span style="color:fuchsia;">(Reading database ... 123500 files and directories currently installed.)</span>
<span style="color:fuchsia;">Removing zoo-dns-setup (1.0-1) ...</span>
<span style="color:fuchsia;">+ dpkg-divert --remove /etc/knot/knot.conf</span>
<span style="color:fuchsia;">Removing 'diversion of /etc/knot/knot.conf to /etc/knot/knot.conf.original by zoo-dns-setup'</span>
<span style="color:fuchsia;"></span><span style="font-weight:bold;color:fuchsia;">HOST 5: executing </span><span style="text-decoration:underline;font-weight:bold;color:fuchsia;">dpkg --install zoo-dnssec.deb</span><span style="font-weight:bold;color:fuchsia;"></span>
<span style="color:fuchsia;">Selecting previously unselected package zoo-dns-dnssec.</span>
<span style="color:fuchsia;">(Reading database ... 123497 files and directories currently installed.)</span>
<span style="color:fuchsia;">Preparing to unpack zoo-dnssec.deb ...</span>
<span style="color:fuchsia;">+ dpkg-divert --divert /etc/knot/knot.conf.no-dnssec --rename /etc/knot/knot.conf</span>
<span style="color:fuchsia;">Adding 'diversion of /etc/knot/knot.conf to /etc/knot/knot.conf.no-dnssec by zoo-dns-dnssec'</span>
<span style="color:fuchsia;">Unpacking zoo-dns-dnssec (1.0-1) ...</span>
<span style="color:fuchsia;">Setting up zoo-dns-dnssec (1.0-1) ...</span>
<span style="color:fuchsia;">+ knotc reload</span>
<span style="color:fuchsia;"></span>
<span style="color:#ff6e6e;"></span><span style="font-weight:bold;color:#ff6e6e;">HOST 1: executing </span><span style="text-decoration:underline;font-weight:bold;color:#ff6e6e;">dpkg --install client-resolver.deb</span><span style="font-weight:bold;color:#ff6e6e;"></span>
<span style="color:#ff6e6e;">Selecting previously unselected package client-dns-resolver.</span>
<span style="color:#ff6e6e;">(Reading database ... 123535 files and directories currently installed.)</span>
<span style="color:#ff6e6e;">Preparing to unpack client-resolver.deb ...</span>
<span style="color:#ff6e6e;">+ dpkg-divert --divert /etc/resolvconf/resolv.conf.d/head.original --rename /etc/resolvconf/resolv.conf.d/head</span>
<span style="color:#ff6e6e;">Adding 'diversion of /etc/resolvconf/resolv.conf.d/head to /etc/resolvconf/resolv.conf.d/head.original by client-dns-resolver'</span>
<span style="color:#ff6e6e;">+ dpkg-divert --divert /etc/bind/db.root.original --rename /etc/bind/db.root</span>
<span style="color:#ff6e6e;">Adding 'diversion of /etc/bind/db.root to /etc/bind/db.root.original by client-dns-resolver'</span>
<span style="color:#ff6e6e;">Unpacking client-dns-resolver (1.0-1) ...</span>
<span style="color:#ff6e6e;">Setting up client-dns-resolver (1.0-1) ...</span>
<span style="color:yellow;"> -----------------------------------------------------------------------------
|                                                                             |
| </span><span style="color:#a9a9fc;">A lot of things just happened - let's go through them.                     </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">First we update the root DNS server to use DNSSEC. We've pre-populated the </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">debian packages for both DNS servers to have functional DNSKEY and RRSIG   </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">and DS records. Take a look in the debian packages to see the details.     </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">DNSSEC for the client doesn't come for free however - they must do some    </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">work to start using all this clever cryptography. We certainly can't       </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">utilize the ISP's caching resolver anymore, so we must setup our own.      </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">Luckily this is pretty simple to do. We install bind, and flip on the      </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">dnssec-validation flag. Bind ships with the real root DNSKEYs for the      </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">internet, but we have a different one, so we must modify /etc/bind/db.root </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">to contain our root server's DNSKEY. We've prepoulated this key in the     </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">client as well via the debian package.                                     </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">Now that the client is configured, even if the ISP does an NXDOMAIN attack </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">on other-isp.zoo, we can skip over its resolvers and the real response.    </span><span style="color:yellow;"> |
|                                                                             |
-----------------------------------------------------------------------------
</span><span style="color:lime;"></span><span style="font-weight:bold;color:lime;">HOST 2: executing </span><span style="text-decoration:underline;font-weight:bold;color:lime;">/root/select-attack nxdomain</span><span style="font-weight:bold;color:lime;"></span>
<span style="color:lime;">creating symlink</span>
<span style="color:#ff6e6e;"></span><span style="font-weight:bold;color:#ff6e6e;">HOST 1: executing </span><span style="text-decoration:underline;font-weight:bold;color:#ff6e6e;">dig other-isp.zoo</span><span style="font-weight:bold;color:#ff6e6e;"></span>
<span style="color:#ff6e6e;"></span>
<span style="color:#ff6e6e;">; &lt;&lt;&gt;&gt; DiG 9.10.3-P4-Ubuntu &lt;&lt;&gt;&gt; other-isp.zoo</span>
<span style="color:#ff6e6e;">;; global options: +cmd</span>
<span style="color:#ff6e6e;">;; Got answer:</span>
<span style="color:#ff6e6e;">;; -&gt;&gt;HEADER&lt;&lt;- opcode: QUERY, status: NOERROR, id: 28629</span>
<span style="color:#ff6e6e;">;; flags: qr rd ra ad; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1</span>
<span style="color:#ff6e6e;"></span>
<span style="color:#ff6e6e;">;; OPT PSEUDOSECTION:</span>
<span style="color:#ff6e6e;">; EDNS: version: 0, flags:; udp: 4096</span>
<span style="color:#ff6e6e;">;; QUESTION SECTION:</span>
<span style="color:#ff6e6e;">;other-isp.zoo.			IN	A</span>
<span style="color:#ff6e6e;"></span>
<span style="color:#ff6e6e;">;; ANSWER SECTION:</span>
<span style="color:#ff6e6e;">other-isp.zoo.		3600	IN	A	10.4.9.4</span>
<span style="color:#ff6e6e;"></span>
<span style="color:#ff6e6e;">;; Query time: 6 msec</span>
<span style="color:#ff6e6e;">;; SERVER: 127.0.0.1#53(127.0.0.1)</span>
<span style="color:#ff6e6e;">;; WHEN: Wed Nov 20 21:01:41 EST 2019</span>
<span style="color:#ff6e6e;">;; MSG SIZE  rcvd: 58</span>
<span style="color:#ff6e6e;"></span>
<span style="color:yellow;"> ------------------------------------------------------------------------------
|                                                                              |
| </span><span style="color:#a9a9fc;">Boom. We've circumvented the ISP's RPZ blocking and we even have proof that </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">the records are authentic because we have strict dnssec-validation! Dig     </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">also provides us with &quot;ad&quot; flag if the response is authenticated.           </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">                                                                            </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">    ;; flags: qr rd ra ad; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1 </span><span style="color:yellow;"> |
|                                                                              |
------------------------------------------------------------------------------
</span><span style="color:yellow;"> ------------------------------------------------------------------------------
|                                                                              |
| </span><span style="color:#a9a9fc;">We still have a problem though, since the ISP can see all of our cleartext  </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">UDP packets flying over port 53, they can just block them. This will result </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">in identical behavior the DROP RPZ attack from the clients perspective.     </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">The ISP can block all DNS requests for other-isp.zoo with a single iptables </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">command.                                                                    </span><span style="color:yellow;"> |
|                                                                              |
------------------------------------------------------------------------------
</span><span style="color:lime;"></span><span style="font-weight:bold;color:lime;">HOST 2: executing </span><span style="text-decoration:underline;font-weight:bold;color:lime;">dpkg --install dns-iptables-block.deb</span><span style="font-weight:bold;color:lime;"></span>
<span style="color:lime;">Selecting previously unselected package dn-iptables-block.</span>
<span style="color:lime;">(Reading database ... 123512 files and directories currently installed.)</span>
<span style="color:lime;">Preparing to unpack dns-iptables-block.deb ...</span>
<span style="color:lime;">+ iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|09|other-isp|03|zoo|' --algo bm -j DROP</span>
<span style="color:lime;">Unpacking dn-iptables-block (1.0-1) ...</span>
<span style="color:lime;">Setting up dn-iptables-block (1.0-1) ...</span>
<span style="color:yellow;"> -----------------------------------------------------------------------------
|                                                                             |
| </span><span style="color:#a9a9fc;">The ISP is now blocking all UDP packets on port 53 that have literally any </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">mention of other-isp.zoo.                                                  </span><span style="color:yellow;"> |
|                                                                             |
-----------------------------------------------------------------------------
</span><span style="color:yellow;"> ----------------------------------------------------------------------
|                                                                      |
| </span><span style="color:#a9a9fc;">Let's wipe the clients cache to make sure we don't just see the old </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">response.                                                           </span><span style="color:yellow;"> |
|                                                                      |
----------------------------------------------------------------------
</span><span style="color:#ff6e6e;"></span><span style="font-weight:bold;color:#ff6e6e;">HOST 1: executing </span><span style="text-decoration:underline;font-weight:bold;color:#ff6e6e;">rndc flush</span><span style="font-weight:bold;color:#ff6e6e;"></span>
<span style="color:#ff6e6e;"></span><span style="font-weight:bold;color:#ff6e6e;">HOST 1: executing </span><span style="text-decoration:underline;font-weight:bold;color:#ff6e6e;">rndc reload</span><span style="font-weight:bold;color:#ff6e6e;"></span>
<span style="color:#ff6e6e;">server reload successful</span>
<span style="color:yellow;"> ------------------------------------------------------
|                                                      |
| </span><span style="color:#a9a9fc;">Now when we dig, our packets never make it through. </span><span style="color:yellow;"> |
|                                                      |
------------------------------------------------------
</span><span style="color:#ff6e6e;"></span><span style="font-weight:bold;color:#ff6e6e;">HOST 1: executing </span><span style="text-decoration:underline;font-weight:bold;color:#ff6e6e;">dig other-isp.zoo +tries=1 +time=3 @127.0.0.1</span><span style="font-weight:bold;color:#ff6e6e;"></span>
<span style="color:#ff6e6e;"></span>
<span style="color:#ff6e6e;">; &lt;&lt;&gt;&gt; DiG 9.10.3-P4-Ubuntu &lt;&lt;&gt;&gt; other-isp.zoo +tries=1 +time=3 @127.0.0.1</span>
<span style="color:#ff6e6e;">;; global options: +cmd</span>
<span style="color:#ff6e6e;">;; connection timed out; no servers could be reached</span>
<span style="color:yellow;"> -----------------------------------------------------------------------
|                                                                       |
| </span><span style="color:#a9a9fc;">We can confirm our rule caught the packets by looking at the iptable </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">counters on the ISP router.                                          </span><span style="color:yellow;"> |
|                                                                       |
-----------------------------------------------------------------------
</span><span style="color:lime;"></span><span style="font-weight:bold;color:lime;">HOST 2: executing </span><span style="text-decoration:underline;font-weight:bold;color:lime;">iptables -L -v</span><span style="font-weight:bold;color:lime;"></span>
<span style="color:lime;">Chain INPUT (policy ACCEPT 34 packets, 6245 bytes)</span>
<span style="color:lime;">pkts bytes target     prot opt in     out     source               destination</span>
<span style="color:lime;">0     0 DROP       all  --  any    any     anywhere             anywhere             MAC 00:15:C5:60:51:23</span>
<span style="color:lime;"></span>
<span style="color:lime;">Chain FORWARD (policy ACCEPT 24 packets, 5061 bytes)</span>
<span style="color:lime;">pkts bytes target     prot opt in     out     source               destination</span>
<span style="color:lime;">4   280 DROP       udp  --  any    any     anywhere             anywhere             udp dpt:domain STRING match  &quot;|096f746865722d697370037a6f6f|&quot; ALGO name bm TO 65535</span>
<span style="color:lime;"></span>
<span style="color:lime;">Chain OUTPUT (policy ACCEPT 24 packets, 4733 bytes)</span>
<span style="color:lime;">pkts bytes target     prot opt in     out     source               destination</span>
<span style="color:yellow;"> --------------------------------------------------------------------------
|                                                                          |
| </span><span style="color:#a9a9fc;">As expected, our dns traffic going through the router for other domains </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">still works.                                                            </span><span style="color:yellow;"> |
|                                                                          |
--------------------------------------------------------------------------
</span><span style="color:#ff6e6e;"></span><span style="font-weight:bold;color:#ff6e6e;">HOST 1: executing </span><span style="text-decoration:underline;font-weight:bold;color:#ff6e6e;">dig bombast.zoo @127.0.0.1 +short</span><span style="font-weight:bold;color:#ff6e6e;"></span>
<span style="color:#ff6e6e;">10.4.9.2</span>
<span style="color:yellow;"> ---------------------------------------------------------------------------
|                                                                           |
| </span><span style="color:#a9a9fc;">So this isn't fun, even if we are using our own resolver and strongly    </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">verifying DNSSEC, our ISP can still block whatever they want - they just </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">can't lie to our faces.                                                  </span><span style="color:yellow;"> |
|                                                                           |
---------------------------------------------------------------------------
</span>
███████╗███████╗██╗  ██╗    ██╗   ██╗██████╗ ███╗   ██╗
██╔════╝██╔════╝██║  ██║    ██║   ██║██╔══██╗████╗  ██║
███████╗███████╗███████║    ██║   ██║██████╔╝██╔██╗ ██║
╚════██║╚════██║██╔══██║    ╚██╗ ██╔╝██╔═══╝ ██║╚██╗██║
███████║███████║██║  ██║     ╚████╔╝ ██║     ██║ ╚████║
╚══════╝╚══════╝╚═╝  ╚═╝      ╚═══╝  ╚═╝     ╚═╝  ╚═══╝

<span style="color:yellow;"> -----------------------------------------------------------------------------
|                                                                             |
| </span><span style="color:#a9a9fc;">In order to get around the ISP droping our packets, we need to encrypt our </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">traffic somehow. We could use DNS over TLS to accomplish this, but support </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">for this protocol isn't widespread yet. Using a VPN makes it so that the   </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">ISP cannot see what requests we are sending out, they can only see that we </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">are doing something. Clearly blocking all of your client's traffic because </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">they might be using other-isp.zoo is too drastic of a move for the ISP.    </span><span style="color:yellow;"> |
|                                                                             |
-----------------------------------------------------------------------------
</span><span style="color:yellow;"> ---------------------------------------------------------------------------
|                                                                           |
| </span><span style="color:#a9a9fc;">We've created an extremely barebones VPN using an SSH tunnel and a       </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">corresponding debian package. Let's go ahead and install that.           </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">Much earlier, during the deploy phase the VPN host was created on host 3 </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">and configured to allow root connections from the clients ssh pubkey.    </span><span style="color:yellow;"> |
|                                                                           |
---------------------------------------------------------------------------
</span><span style="color:#ff6e6e;"></span><span style="font-weight:bold;color:#ff6e6e;">HOST 1: executing </span><span style="text-decoration:underline;font-weight:bold;color:#ff6e6e;">dpkg --install vpn-client.deb</span><span style="font-weight:bold;color:#ff6e6e;"></span>
<span style="color:#ff6e6e;">Selecting previously unselected package vpn-client.</span>
<span style="color:#ff6e6e;">(Reading database ... 123538 files and directories currently installed.)</span>
<span style="color:#ff6e6e;">Preparing to unpack vpn-client.deb ...</span>
<span style="color:#ff6e6e;">Unpacking vpn-client (1.0-1) ...</span>
<span style="color:#ff6e6e;">Setting up vpn-client (1.0-1) ...</span>
<span style="color:#ff6e6e;">+ sysctl -w net.ipv4.ip_forward=1</span>
<span style="color:#ff6e6e;">net.ipv4.ip_forward = 1</span>
<span style="color:yellow;"> -----------------------------------------------------------------------
|                                                                       |
| </span><span style="color:#a9a9fc;">We use ssh to open up tunnel interfaces and route traffic to the DNS </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">servers through this tunnel.                                         </span><span style="color:yellow;"> |
|                                                                       |
-----------------------------------------------------------------------
</span><span style="color:#ff6e6e;"></span><span style="font-weight:bold;color:#ff6e6e;">HOST 1: executing </span><span style="text-decoration:underline;font-weight:bold;color:#ff6e6e;">ifup tun0</span><span style="font-weight:bold;color:#ff6e6e;"></span>
<span style="color:#ff6e6e;">Warning: Permanently added '10.4.9.3' (ECDSA) to the list of known hosts.
</span>
<span style="color:yellow;"></span><span style="font-weight:bold;color:yellow;">HOST 3: executing </span><span style="text-decoration:underline;font-weight:bold;color:yellow;">ifup tun0</span><span style="font-weight:bold;color:yellow;"></span>
<span style="color:#ff6e6e;"></span><span style="font-weight:bold;color:#ff6e6e;">HOST 1: executing </span><span style="text-decoration:underline;font-weight:bold;color:#ff6e6e;">ip route</span><span style="font-weight:bold;color:#ff6e6e;"></span>
<span style="color:#ff6e6e;">10.0.0.0/8 dev eth0  proto kernel  scope link  src 10.4.9.1</span>
<span style="color:#ff6e6e;">10.4.9.0/24 via 10.4.9.2 dev eth0</span>
<span style="color:#ff6e6e;">10.4.9.5 via 192.168.9.3 dev tun0</span>
<span style="color:#ff6e6e;">10.4.9.6 via 192.168.9.3 dev tun0</span>
<span style="color:#ff6e6e;">192.168.9.3 dev tun0  proto kernel  scope link  src 192.168.9.1</span>
<span style="color:yellow;"> ------------------------------------------------------------------------------
|                                                                              |
| </span><span style="color:#a9a9fc;">Now all of our DNS traffic goes through this tunnel and pops out the other  </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">side on host 3. We apply NAT to the packets so the DNS servers will now see </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">traffic coming from 10.4.9.3 instead of 10.4.9.1.                           </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">Even though the ISP is blocking DNS packets referencing other-isp.zoo, we   </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">can now run a DNS query against that domain succesfully!                    </span><span style="color:yellow;"> |
|                                                                              |
------------------------------------------------------------------------------
</span><span style="color:#ff6e6e;"></span><span style="font-weight:bold;color:#ff6e6e;">HOST 1: executing </span><span style="text-decoration:underline;font-weight:bold;color:#ff6e6e;">dig other-isp.zoo @127.0.0.1</span><span style="font-weight:bold;color:#ff6e6e;"></span>
<span style="color:#ff6e6e;"></span>
<span style="color:#ff6e6e;">; &lt;&lt;&gt;&gt; DiG 9.10.3-P4-Ubuntu &lt;&lt;&gt;&gt; other-isp.zoo @127.0.0.1</span>
<span style="color:#ff6e6e;">;; global options: +cmd</span>
<span style="color:#ff6e6e;">;; Got answer:</span>
<span style="color:#ff6e6e;">;; -&gt;&gt;HEADER&lt;&lt;- opcode: QUERY, status: NOERROR, id: 10717</span>
<span style="color:#ff6e6e;">;; flags: qr rd ra ad; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1</span>
<span style="color:#ff6e6e;"></span>
<span style="color:#ff6e6e;">;; OPT PSEUDOSECTION:</span>
<span style="color:#ff6e6e;">; EDNS: version: 0, flags:; udp: 4096</span>
<span style="color:#ff6e6e;">;; QUESTION SECTION:</span>
<span style="color:#ff6e6e;">;other-isp.zoo.			IN	A</span>
<span style="color:#ff6e6e;"></span>
<span style="color:#ff6e6e;">;; ANSWER SECTION:</span>
<span style="color:#ff6e6e;">other-isp.zoo.		3600	IN	A	10.4.9.4</span>
<span style="color:#ff6e6e;"></span>
<span style="color:#ff6e6e;">;; Query time: 4 msec</span>
<span style="color:#ff6e6e;">;; SERVER: 127.0.0.1#53(127.0.0.1)</span>
<span style="color:#ff6e6e;">;; WHEN: Wed Nov 20 21:02:02 EST 2019</span>
<span style="color:#ff6e6e;">;; MSG SIZE  rcvd: 58</span>
<span style="color:#ff6e6e;"></span>
<span style="color:yellow;"> ---------------------------------------------------------------------------
|                                                                           |
| </span><span style="color:#a9a9fc;">We have defeated bombast's attempts to censor other-isp.zoo and          </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">furthurmore, they can no longer see what sites we are visiting! However, </span><span style="color:yellow;"> |
| </span><span style="color:#a9a9fc;">whoever owns the VPN host can.                                           </span><span style="color:yellow;"> |
|                                                                           |
---------------------------------------------------------------------------
</pre>
</div>
