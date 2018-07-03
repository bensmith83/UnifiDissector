-- Declare protocol for dissection
unifi_proto = Proto("unifi", "Unifi Discovery Protocol")

-- Specifiy protocol fields
unifi_proto.fields.payload_len = ProtoField.uint32("unifi.payload_len", "Payload Length")
unifi_proto.fields.preamble2_mac = ProtoField.ether("unifi.src_mac", "Source MAC")
unifi_proto.fields.src_ip = ProtoField.ipv4("unifi.src_ip", "Src IP")
unifi_proto.fields.source_mac = ProtoField.ether("unifi.mac", "MAC")
unifi_proto.fields.time = ProtoField.relative_time("unifi.time", "Time Offset")
unifi_proto.fields.name = ProtoField.string("unifi.name", "Name")
unifi_proto.fields.shortname = ProtoField.string("unifi.shortname", "Board Shortname")
unifi_proto.fields.firmware = ProtoField.string("unifi.firmware", "Firmware")
unifi_proto.fields.version = ProtoField.string("unifi.version", "Version")
unifi_proto.fields.numbers = ProtoField.string("unifi.shortname_again", "Product Code, Again")
unifi_proto.fields.build = ProtoField.string("unifi.build", "Build")
unifi_proto.fields.shortname_again = ProtoField.string("unifi.shortname_again", "Shortname")
unifi_proto.fields.required_fw_version = ProtoField.string("unifi.required_fw_version", "Board Required Firmware Version")
unifi_proto.fields.seventeen = ProtoField.bytes("unifi.seventeen", "Unknown - seventeen")
unifi_proto.fields.eighteen = ProtoField.bytes("unifi.eighteen", "Unknown - eighteen")
unifi_proto.fields.nineteen = ProtoField.bytes("unifi.nineteen", "Unknown - nineteen")
unifi_proto.fields.oneayy = ProtoField.bytes("unifi.oneayy", "Unknown - oneayy")
unifi_proto.fields.mac_address_again = ProtoField.ether("unifi.mac_address_again", "MAC")
unifi_proto.fields.count = ProtoField.uint32("unifi.count", "Packet Count")
unifi_proto.fields.ten = ProtoField.bytes("unifi.ten", "Unknown - ten")
unifi_proto.fields.request = ProtoField.string("unifi.request", "Request")
unifi_proto.fields.unknown = ProtoField.bytes("unifi.unknown", "Unknown")

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
    if (blip == 0x01 and blap == 0x00) or (blip == 0x02 and blap == 0x06) then
        ogtree:add(unifi_proto.fields.payload_len, buffer(3, 1), payload_len)
        unktree = ogtree:add(unifi_proto.fields.unknown, "Unknown", "Unknown")
        if (blip == 0x01 and blap == 0x00 and payload_len == 0x00) then
            ogtree:add(unifi_proto.fields.request, buffer(3,1), "Request")
        end
        pkt_ptr = 4
        while pkt_ptr<payload_len +4 do
--            info("pkt_ptr: "..pkt_ptr)
            temp_type = buffer(pkt_ptr, 1):uint()
--            info("temp_type: "..temp_type)
            pkt_ptr = pkt_ptr +1
--            info("pkt_ptr: "..pkt_ptr)
            temp_len = buffer(pkt_ptr, 2):uint()
--            info("temp_len: "..temp_len)
            pkt_ptr = pkt_ptr + 2
--            info("pkt_ptr: "..pkt_ptr)
            add_lookup_type(temp_type, temp_len, pkt_ptr, ogtree, unktree, buffer, payload_len + 4)
            pkt_ptr = pkt_ptr + temp_len
        end
--        info("end loop: pkt_ptr: "..pkt_ptr.."; payload_len: "..payload_len.."; temp_len: "..temp_len)
    end
end

function add_lookup_type(field_type, field_len, field_value_ptr, tree, unktree, buffer, payload_len)
    if field_value_ptr + field_len > payload_len then
        return
    end
    if field_type == 0x01 then
		 -- MAC
        tree:add(unifi_proto.fields.source_mac, buffer(field_value_ptr, field_len))
	end
	if field_type == 0x02 then
		 -- MAC & 4 bytes that remain static per device
        subtree = tree:add(buffer(field_value_ptr, field_len), "Source Info")
        subtree:add(unifi_proto.fields.preamble2_mac, buffer(field_value_ptr, field_len - 4))
        subtree:add(unifi_proto.fields.src_ip, buffer(field_value_ptr + 6, 4))
	end
	if field_type == 0x03 then
		 -- firmware
        tree:add(unifi_proto.fields.firmware, buffer(field_value_ptr, field_len))
	end
	if field_type == 0x0A then
		 -- 4 bytes that increment every 5 seconds
        tree:add(unifi_proto.fields.time, buffer(field_value_ptr, field_len))
	end
	if field_type == 0x0B then
		 -- Name then
		 -- common name given to the device or hostname
        tree:add(unifi_proto.fields.name, buffer(field_value_ptr, field_len))
	end
	if field_type == 0x0C then
		 -- product code
        tree:add(unifi_proto.fields.shortname, buffer(field_value_ptr, field_len))
    end
    if field_type == 0x10 then
		-- ???? 2 bytes	
        unktree:add(unifi_proto.fields.ten, buffer(field_value_ptr, field_len))
	end
	if field_type == 0x12 then
		 -- 4 bytes that change or increment every packet
        tree:add(unifi_proto.fields.count, buffer(field_value_ptr, field_len))
	end
	if field_type== 0x13 then
		 -- MAC
        tree:add(unifi_proto.fields.mac_address_again, buffer(field_value_ptr, field_len))
	end
	if field_type == 0x15 then
		 -- product code
        tree:add(unifi_proto.fields.shortname_again, buffer(field_value_ptr, field_len))
	end
	if field_type == 0x16 then
		 -- version
        tree:add(unifi_proto.fields.version, buffer(field_value_ptr, field_len))
	end
	if field_type == 0x17 then
		 -- ????
        unktree:add(unifi_proto.fields.seventeen, buffer(field_value_ptr, field_len))
	end
	if field_type == 0x18 then
		 -- ????
        unktree:add(unifi_proto.fields.eighteen, buffer(field_value_ptr, field_len))
	end
	if field_type == 0x19 then
		 -- ????
		unktree:add(unifi_proto.fields.nineteen, buffer(field_value_ptr, field_len))
	end
	if field_type == 0x1A then
		 -- ????
        unktree:add(unifi_proto.fields.oneayy, buffer(field_value_ptr, field_len))
	end
	if field_type == 0x1B then
		 -- version - likely the backup firmware on the device
--        info("1b req_fw: field_value_ptr: "..field_value_ptr.."; field_len: "..field_len)
        tree:add(unifi_proto.fields.required_fw_version, buffer(field_value_ptr, field_len))
    end
end

-- get UDP dissector table and add for port 10001
udp_table = DissectorTable.get("udp.port")
udp_table:add(10001, unifi_proto)
