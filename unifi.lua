-- Declare protocol for dissection
unifi_proto = Proto("unifi", "Unifi Broadcast Protocol")

-- Specifiy protocol fields
unifi_proto.fields.payload_len = ProtoField.uint32("unifi.payload_len", "Payload Length")
unifi_proto.fields.preamble = ProtoField.bytes("unifi.preamble", "Preamble")
unifi_proto.fields.preamble2_mac = ProtoField.bytes("unifi.preamble2_mac", "Preamble2 MAC")
unifi_proto.fields.preamble2 = ProtoField.bytes("unifi.preamble2", "Preamble2 - Static")
unifi_proto.fields.source_mac = ProtoField.bytes("unifi.source_mac", "Source MAC")
unifi_proto.fields.preamble3 = ProtoField.bytes("unifi.preamble3", "Preamble3 - Counter")
unifi_proto.fields.name = ProtoField.string("unifi.name", "Name")
unifi_proto.fields.product_code = ProtoField.string("unifi.product_code", "Product Code")
unifi_proto.fields.firmware = ProtoField.string("unifi.firmware", "Firmware")
unifi_proto.fields.version = ProtoField.string("unifi.version", "Version")
unifi_proto.fields.numbers = ProtoField.string("unifi.product_code_again", "Product Code, Again")
unifi_proto.fields.build = ProtoField.string("unifi.build", "Build")
unifi_proto.fields.product_code_again = ProtoField.string("unifi.product_code_again", "Product Code Again")
unifi_proto.fields.required_fw_version = ProtoField.string("unifi.required_fw_version", "Board Required Firmware Version")
unifi_proto.fields.seventeen = ProtoField.bytes("unifi.seventeen", "seventeen")
unifi_proto.fields.eighteen = ProtoField.bytes("unifi.eighteen", "eighteen")
unifi_proto.fields.nineteen = ProtoField.bytes("unifi.nineteen", "nineteen")
unifi_proto.fields.oneayy = ProtoField.bytes("unifi.oneayy", "oneayy")
unifi_proto.fields.mac_address_again = ProtoField.bytes("unifi.mac_address_again", "mac_address_again")
unifi_proto.fields.twelve = ProtoField.bytes("unifi.twelve", "twelve - Counter")

-- Global Variables
FIRST_FIELD = 6


-- Dissector function
-- buffer: The TDP packet data as a "Testy Virtual Buffer"
-- pinfo: Packet information
-- tree: Root of the UI tree

function unifi_proto.dissector(buffer, pinfo, tree)
    -- set the name in the protocol column in the UI
    pinfo.cols.protocol = "Unifi"

    -- create sub tree which represents the entire buffer
    local ogtree = tree:add(unifi_proto, buffer(), "Unifi Protocol Data")
    local temp_len = 0
    local pkt_ptr = 0
    local payload_len = buffer(3,1):uint() -- payload len
    ogtree:add(unifi_proto.fields.payload_len, buffer(3, 1), payload_len)
    temp_len = buffer(FIRST_FIELD,1):uint() -- first field len, binary
    subtree = ogtree:add(unifi_proto.fields.preamble, buffer(FIRST_FIELD+1,temp_len))
    subtree:add(unifi_proto.fields.preamble2_mac, buffer(FIRST_FIELD+1, temp_len - 4))
    subtree:add(unifi_proto.fields.preamble2, buffer(FIRST_FIELD+1+6, 4))
    pkt_ptr = FIRST_FIELD + temp_len + 3
    temp_len = buffer(pkt_ptr,1):uint()
    ogtree:add(unifi_proto.fields.source_mac, buffer(pkt_ptr+1, temp_len))
    pkt_ptr = pkt_ptr + temp_len + 3
    temp_len = buffer(pkt_ptr,1):uint()
    subtree:add(unifi_proto.fields.preamble3, buffer(pkt_ptr+1, temp_len))
    pkt_ptr = pkt_ptr + temp_len + 3
    temp_len = buffer(pkt_ptr,1):uint()
    ogtree:add(unifi_proto.fields.name, buffer(pkt_ptr+1, temp_len))
    pkt_ptr = pkt_ptr + temp_len + 3
    temp_len = buffer(pkt_ptr,1):uint()
    ogtree:add(unifi_proto.fields.product_code, buffer(pkt_ptr+1, temp_len))
    pkt_ptr = pkt_ptr + temp_len + 3
    temp_len = buffer(pkt_ptr,1):uint()
    ogtree:add(unifi_proto.fields.firmware, buffer(pkt_ptr+1, temp_len))
    pkt_ptr = pkt_ptr + temp_len + 3
    temp_len = buffer(pkt_ptr,1):uint()
    ogtree:add(unifi_proto.fields.version, buffer(pkt_ptr+1, temp_len))
    pkt_ptr = pkt_ptr + temp_len + 3
    temp_len = buffer(pkt_ptr,1):uint()
    ogtree:add(unifi_proto.fields.product_code_again, buffer(pkt_ptr+1, temp_len))
    pkt_ptr = pkt_ptr + temp_len + 3
    temp_len = buffer(pkt_ptr,1):uint()
    subtree = ogtree:add(unifi_proto.fields.seventeen, buffer(pkt_ptr+1, temp_len))
    pkt_ptr = pkt_ptr + temp_len + 3
    temp_len = buffer(pkt_ptr,1):uint()
    subtree:add(unifi_proto.fields.eighteen, buffer(pkt_ptr+1, temp_len))
    pkt_ptr = pkt_ptr + temp_len + 3
    temp_len = buffer(pkt_ptr,1):uint()
    subtree:add(unifi_proto.fields.nineteen, buffer(pkt_ptr+1, temp_len))
    pkt_ptr = pkt_ptr + temp_len + 3
    temp_len = buffer(pkt_ptr,1):uint()
    subtree:add(unifi_proto.fields.oneayy, buffer(pkt_ptr+1, temp_len))
    pkt_ptr = pkt_ptr + temp_len + 3
    temp_len = buffer(pkt_ptr,1):uint()
    subtree:add(unifi_proto.fields.mac_address_again, buffer(pkt_ptr+1, temp_len))
    pkt_ptr = pkt_ptr + temp_len + 3
    temp_len = buffer(pkt_ptr,1):uint()
    subtree:add(unifi_proto.fields.twelve, buffer(pkt_ptr+1, temp_len))
    pkt_ptr = pkt_ptr + temp_len + 3
    temp_len = buffer(pkt_ptr,1):uint()
    ogtree:add(unifi_proto.fields.required_fw_version, buffer(pkt_ptr+1, temp_len))
end

-- get UDP dissector table and add for port 10001
udp_table = DissectorTable.get("udp.port")
udp_table:add(10001, unifi_proto)
