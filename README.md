# UnifiDissector
A quick and dirty LUA dissector for the Unifi broadcast protocol

## Unifi Protocol
Not a formal protocol. I observed a lot of traffic from to broadcast on UDP 10001 and decided to throw together a quick parser to parse the format. A good amount is incomplete, and right now I haven't figured out what the router speaks, so it doesn't parse that. There needs to be some sort of checking to determine the type of message.

## How?
`wireshark -X lua_script:unifi.lua <pcap>.pcap`

[Hey it works!](/img/unifi_lua_1.png)


## Why?
Why not? If you have interesting traffic that doesn't parse, feel free to send it my way.
