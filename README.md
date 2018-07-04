# UnifiDissector
A quick and dirty Lua dissector for the Unifi Discovery protocol

## Unifi Protocol
I observed a lot of traffic from to broadcast on UDP 10001 and decided to throw together a quick parser to parse the format. A good amount is incomplete, and right now I haven't figured out what the router speaks, so it doesn't parse that. There needs to be some sort of checking to determine the type of message.

### General Structure
Payload follows a Type Length Value (TLV) structure. The length seems to be two bytes wide. The types are as follow:

|Type Code|Interpretation|
|---------|--------------|
|0x0206 \| 0x0100| Message start magic bytes|
|0x01     |Source MAC    |
|0x02     |Preamble: MAC & Src IP|
|0x03     |firmware|
|0x0A     |time|
|0x0B     |name|
|0x0C     |shortname|
|0x10     |unknown|
|0x12     |count|
|0x13     |mac address|
|0x15     |shortname|
|0x16     |version|
|0x17     |unknown|
|0x18     |unknown|
|0x19     |unknown|
|0x1A     |unknown|
|0x1B     |Minimum Required Firmware|

Note that there can be multiple preambles and they may represent multiple interfaces.

If you have any suggestions for what some of these unknown fields are, please let me know.

## How?
`wireshark -X lua_script:unifi.lua <pcap>.pcap`

## Really?
![lua_dissector_1](/img/unifi_lua_2.png "Yes.")

## Why?
Why not? If you have interesting traffic that doesn't parse, feel free to send it my way.

## Thanks
Many thanks to James Forshaw's [Attacking Network Protocols](https://nostarch.com/networkprotocols) for showing how easy it is to write Wireshark dissectors, among other great things.
