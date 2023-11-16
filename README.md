# MCQFW
MCQFW is a proxy software designed to bypass Deep Packet Inspection (DPI) by certain firewalls.

# How does it work

## HTTP
Some firewalls only expect header naems to start with a uppercase character, so changing header names to lowercase could bypass the detection.

## HTTPS/TLS
Some firewalls do not have the ability to reassemble tcp packets, so sending the SNI (Server Name Extension in TLS Client Hello) in two separate tcp packets could bypass the detection.

This can be done by enabling NO_DELAY and fragmenting the Client Hello packet.

# Limitations
In TLS1.2, server cerfications are sent in plain text by TLS servers. Therefore, firewalls could obtain the server name from these packets.

One way to bypass this type of detection is setting the TCP window size to a very small number. This forces the server to fragment its TCP packets. However, setting a small window size could impact the connection speed.

# How to use
1. Clone this repo
2. `go build`
3. `./mcqfw -listen 127.0.0.1:8081`
4. Configure your application to use MCQFW's SOCKS5 proxy, for example:
`curl --proxy socks5://127.0.0.1:8081 blacklisted_website.com`

# Credits

[https://github.com/bol-van/zapret/blob/master/docs/readme.eng.md](https://github.com/bol-van/zapret/blob/master/docs/readme.eng.md)