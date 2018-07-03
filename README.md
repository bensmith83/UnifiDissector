# UnifiDissector
A quick and dirty LUA dissector for the Unifi broadcast protocol

## Unifi Protocol
Not a formal protocol. I observed a lot of traffic from to broadcast on UDP 10001 and decided to throw together a quick parser to parse the format. A good amount is incomplete, and right now I haven't figured out what the router speaks, so it doesn't parse that. There needs to be some sort of checking to determine the type of message.

### General Structure
Payload follows a Type Length Value (TLV) structure. The length seems to be two bytes wide. The types are as follow:
0x0206 - begin message
0x02 - MAC & 4 bytes that remain static per device
0x01 - MAC
0x0A - 4 bytes that increment every 5 seconds
0x0B - UBNT
0x0C - product code
0x03 - firmware
0x16 - version
0x15 - product code
0x17 - ????
0x18 - ????
0x19 - ????
0x1A - ????
0x13 - MAC
0x12 - 4 bytes that change or increment every packet
0x1B - version - likely the backup firmware on the device

Right now this doesn't match on the type code above, it expects them in order. This will be fixed soon.

## How?
`wireshark -X lua_script:unifi.lua <pcap>.pcap`

[Hey it works!](/img/unifi_lua_1.png)


## Why?
Why not? If you have interesting traffic that doesn't parse, feel free to send it my way.
