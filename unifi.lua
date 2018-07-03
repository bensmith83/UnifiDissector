-- Declare protocol for dissection
unifi_proto = Proto("unifi", "Unifi Discovery Protocol")

-- Specifiy protocol fields
unifi_proto.fields.payload_len = ProtoField.uint32("unifi.payload_len", "Payload Length")
unifi_proto.fields.preamble = ProtoField.bytes("unifi.preamble", "Preamble")
unifi_proto.fields.preamble2_mac = ProtoField.bytes("unifi.preamble2_mac", "Preamble2 MAC")
unifi_proto.fields.preamble2 = ProtoField.bytes("unifi.preamble2", "Preamble2 - Static")
unifi_proto.fields.source_mac = ProtoField.bytes("unifi.source_mac", "Source MAC")
unifi_proto.fields.preamble3 = ProtoField.bytes("unifi.preamble3", "Preamble3 - Counter")
unifi_proto.fields.name = ProtoField.string("unifi.name", "Name")
unifi_proto.fields.shortname = ProtoField.string("unifi.shortname", "Board Shortname")
unifi_proto.fields.firmware = ProtoField.string("unifi.firmware", "Firmware")
unifi_proto.fields.version = ProtoField.string("unifi.version", "Version")
unifi_proto.fields.numbers = ProtoField.string("unifi.shortname_again", "Product Code, Again")
unifi_proto.fields.build = ProtoField.string("unifi.build", "Build")
unifi_proto.fields.shortname_again = ProtoField.string("unifi.shortname_again", "Product Code Again")
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
    local ogtree = tree:add(unifi_proto, buffer(), "Unifi Discovery")
    local temp_len = 0
    local pkt_ptr = 0
    local payload_len = buffer(3,1):uint() -- payload len
    local temp_type = 0
    blip = buffer(0,1):uint()
    blap = buffer(1,1):uint()
    if (blip == 0x01 and blap == 0x00) or (blip == 0x06 and blap == 0x02) then
        ogtree:add(unifi_proto.fields.payload_len, buffer(3, 1), payload_len)
        pkt_ptr = 5
        while pkt_ptr<payload_len do
            temp_type = buffer(pkt_ptr, 1):uint()
            pkt_ptr = pkt_ptr +1
            temp_len = buffer(pkt_ptr, 2):uint()
            pkt_ptr = pkt_ptr + 2
            add_lookup_type(temp_type, temp_len, pkt_ptr)
        end
    end
end

function add_lookup_type(field_type, field_len, field_value_ptr)
    if field_type == 0x01 then
		 -- MAC
        ogtree:add(unifi_proto.fields.source_mac, buffer(field_value_ptr, field_len))
	end
	if field_type == 0x02 then
		 -- MAC & 4 bytes that remain static per device
        subtree = ogtree:add(unifi_proto.fields.preamble, buffer(field_value_ptr, field_len))
        subtree:add(unifi_proto.fields.preamble2_mac, buffer(field_value_ptr, field_len - 4))
        subtree:add(unifi_proto.fields.preamble2, buffer(field_value_ptr + 6, 4))
	end
	if field_type == 0x03 then
		 -- firmware
        ogtree:add(unifi_proto.fields.firmware, buffer(field_value_ptr, field_len))
	end
	if field_type == 0x0A then
		 -- 4 bytes that increment every 5 seconds
        ogtree:add(unifi_proto.fields.preamble3, buffer(field_value_ptr, field_len))
	end
	if field_type == 0x0B then
		 -- Name then
		 -- common name given to the device or hostname
        ogtree:add(unifi_proto.fields.name, buffer(field_value_ptr, field_len))
	end
	if field_type == 0x0C then
		 -- product code
        ogtree:add(unifi_proto.fields.shortname, buffer(field_value_ptr, field_len))
    end
    --else if field_type == 0x10 then
		 -- ???? 2 bytes	
        -- TODO: addme
	--end
	if field_type == 0x12 then
		 -- 4 bytes that change or increment every packet
        ogtree:add(unifi_proto.fields.twelve, buffer(field_value_ptr, field_len))
	end
	if field_type== 0x13 then
		 -- MAC
        ogtree:add(unifi_proto.fields.mac_address_again, buffer(field_value_ptr, field_len))
	end
	if field_type == 0x15 then
		 -- product code
        ogtree:add(unifi_proto.fields.shortname_again, buffer(field_value_ptr, field_len))
	end
	if field_type == 0x16 then
		 -- version
        ogtree:add(unifi_proto.fields.version, buffer(field_value_ptr, field_len))
	end
	if field_type == 0x17 then
		 -- ????
        --unktree = 
        ogtree:add(unifi_proto.fields.seventeen, buffer(field_value_ptr, field_len))
	end
	if field_type == 0x18 then
		 -- ????
        --unktree = 
        ogtree:add(unifi_proto.fields.eighteen, buffer(field_value_ptr, field_len))
	end
	if field_type == 0x19 then
		 -- ????
        --unktree = 
        ogtree:add(unifi_proto.fields.nineteen, buffer(field_value_ptr, field_len))
	end
	if field_type == 0x1A then
		 -- ????
        --unktree = 
        ogtree:add(unifi_proto.fields.oneayy, buffer(field_value_ptr, field_len))
	end
	if field_type == 0x1B then
		 -- version - likely the backup firmware on the device
        ogtree:add(unifi_proto.fields.required_fw_version, buffer(field_value_ptr, field_len))
    end
end

-- get UDP dissector table and add for port 10001
udp_table = DissectorTable.get("udp.port")
udp_table:add(10001, unifi_proto)
