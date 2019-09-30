---------------------------------
--- @file synCookie.lua
--- @brief TCP SYN cookie implementation.
--- Includes:
--- - calculate and verify a cookie
--- - functions to build and verify each part of the cookie
--- - necessary packet crafting for responses
--- - necessary buffers
--- - state keeping for cookie
---------------------------------

local ffi		= require "ffi"
local log		= require "log"
local memory	= require "memory"
local proto		= require "proto/proto"
local libmoon	= require "libmoon" -- for getTime
require "utils"

local bor, bxor, band, bnot, rshift, lshift= bit.bor, bit.bxor, bit.band, bit.bnot, bit.rshift, bit.lshift
local time = time

local clib = ffi.load("build/proxy")


---------------------------------------------------
-- Terminology
---------------------------------------------------

-- left: outside, internet, clients, potential attackers, whatever
-- right: "protected" side, connection to server(s), only filtered traffic comes here

local SERVER_IP = parseIP4Address("10.0.0.1")
local CLIENT_MAC = parseMacAddress("00:1b:21:be:39:16")
local CLIENT_MAC_64 = CLIENT_MAC:get()
local ATTACKER_MAC = parseMacAddress("00:1b:21:be:39:14")
local ATTACKER_MAC_64 = ATTACKER_MAC:get()
local SERVER_MAC = parseMacAddress("ac:1f:6b:7a:71:cc")
local SERVER_MAC_64 = SERVER_MAC:get()
local PROXY_MAC_LEFT  = parseMacAddress("ac:1f:6b:4d:a3:e5") 
local PROXY_MAC_LEFT_64 = PROXY_MAC_LEFT:get()
local PROXY_MAC_RIGHT  = parseMacAddress("00:1b:21:be:38:ee") 
local PROXY_MAC_RIGHT_64 = PROXY_MAC_RIGHT:get()

local mod = {}

-------------------------------------------------------------------------------------------
---- Timestamp
-------------------------------------------------------------------------------------------

-- one cycle is 64 seconds (6 bit right shift of timestamp)
local timestampValidCycles = 2

local function getTimestamp()
	local t = libmoon.getTime()
	-- 64 seconds resolution
	t = rshift(t, 6)
	-- 5 bits
	t = t % 32
	return t
end

local function verifyTimestamp(t)
	return t + timestampValidCycles >= getTimestamp()
end


-------------------------------------------------------------------------------------------
---- Option extracting
-------------------------------------------------------------------------------------------

local function extractOptions(pkt)
	-- get MSS and WSOPT options
	local offset = pkt.tcp:getDataOffset() - 5 -- options length in 32 bits (deduct 5 for standard tcp header length)
	local mss = nil
	local upper = 0
	local lower = 0

	local wsopt = nil
	local tsval = false
	local opt = 0
	local i = 0
	while i < offset * 4 do
		opt = pkt.payload.uint8[i]
		if opt == 2 then -- MSS option type
			-- alignment is not guaranteed, build uint16 from uint8s
			upper = pkt.payload.uint8[i + 2]
			lower = pkt.payload.uint8[i + 3]
			mss = lshift(upper, 8) + lower
			i = i + 4
		elseif opt == 3 then
			wsopt = pkt.payload.uint8[i + 2]
			i = i + 3
		elseif opt == 8 then
			tsval = true
			i = i + 10
		elseif opt == 0 then
			-- signals end
			break
		elseif opt == 1 then
			-- nop padding
			i = i + 1
		else
			-- other options
			i = i + pkt.payload.uint8[i + 1] -- increment by option length
		end
	end
	return mss, wsopt, tsval
end


-------------------------------------------------------------------------------------------
---- TCP Options
-------------------------------------------------------------------------------------------

-- MSS encodings
local MSS = { }
MSS[1] = 1460
MSS[2] = 1360
MSS[3] = 1260
MSS[4] = 1160
MSS[5] = 960
MSS[6] = 760
MSS[7] = 536
MSS[8] = nil -- not set

-- always round down to next MSS value
local function encodeMss(mss)
	-- 3 bits, allows for 8 different MSS
	if not mss then
		return 7 -- not set
	end
	for i = 1, 7 do
		if mss >= MSS[i] then
			return i - 1 -- convert to 0-7
		end
	end
	return 6 -- below minimum (weird, but set minimum?!)
end

local function decodeMss(idx)
	return MSS[idx + 1] or 536
end

-- we can encode values 0 - 14 (everything above is 14)
-- value 15 means no option set
local function encodeWsopt(wsopt)
	if not wsopt then
		return 15
	end
	if wsopt > 14 then
		return 14
	end
	return wsopt
end

local function decodeWsopt(wsopt)
	if wsopt == 15 then
		return nil
	end
	return wsopt
end


-------------------------------------------------------------------------------------------
---- Hash
-------------------------------------------------------------------------------------------

ffi.cdef [[
	struct sipkey {
		uint64_t k[2];
	}; /* struct sipkey */

	struct sipkey * mg_siphash_cookie_init();
	uint32_t mg_siphash_cookie_hash(struct sipkey *key,	uint32_t ip_src, uint32_t ip_dst, uint16_t tcp_src, uint16_t tcp_dst, uint32_t ts);
]]

local siphashCookie = {}
siphashCookie.__index = siphashCookie

function mod.initSiphashCookie()
	log:info("Generating key material for cookie siphash")
	local k = clib.mg_siphash_cookie_init()
	return setmetatable({
		key = k
	}, siphashCookie)
end

function siphashCookie:hash(ipSrc, ipDst, portSrc, portDst, ts)
	return tonumber(clib.mg_siphash_cookie_hash(self.key, ipSrc, ipDst, portSrc, portDst, ts))
end

---- Siphash instance
local hasher = mod.initSiphashCookie()

local function getHash(ipSrc, ipDst, portSrc, portDst, ts)
	return hasher:hash(ipSrc, ipDst, portSrc, portDst, ts)
end

local function verifyHash(oldHash, ipSrc, ipDst, portSrc, portDst, ts)
	local newHash = getHash(ipSrc, ipDst, portSrc, portDst, ts)
	-- log:debug('Old hash:       ' .. toBinary(oldHash))
	-- log:debug('New hash:       ' .. toBinary(newHash))
	return oldHash == newHash
end


-------------------------------------------------------------------------------------------
---- Cookie crafting
-------------------------------------------------------------------------------------------

local function calculateCookie(pkt)
	--------------------------------------
	---- LAYOUT Original
	---- ts 5 - mss 3 - hash 24
	---- LAYOUT with wsopt
	---- ts 5 - mss 3 - wsopt 4 - hash 20
	--------------------------------------
	
	-- timestamp and hash involve C calls, hence, are done for the whole batch in C

	-- extra options we support
	local mss, wsopt = extractOptions(pkt)
	mss = encodeMss(mss)
	mss = lshift(mss, 24)

	wsopt = encodeWsopt(wsopt)
	wsopt = lshift(wsopt, 20)
	
	local cookie = mss + wsopt
	return cookie
end

function mod.verifyCookie(pkt)
	if pkt.eth.src:get() == SERVER_MAC_64 then
		--log:warn("Verify cookie from Server -> drop")
		return false
	end

	local cookie = pkt.tcp:getAckNumber()
	cookie = cookie - 1

	-- check timestamp first
	local ts = rshift(cookie, 27)
	if not verifyTimestamp(ts) then
		--log:warn('Received cookie with invalid timestamp')
		return false
	end

	-- check hash
	local hash = band(cookie, 0x000fffff)
	if not verifyHash(
			hash, 
			pkt.ip4:getSrc(), 
			pkt.ip4:getDst(), 
			pkt.tcp:getSrc(), 
			pkt.tcp:getDst(), 
			ts
	) then
		--log:warn('Received cookie with invalid hash')
		return false
	else
		-- finally decode options and return it
		--log:debug('Received legitimate cookie')
		local mss = decodeMss(band(rshift(cookie, 24), 0x7))
		local wsopt = decodeWsopt(band(rshift(cookie, 20), 0xf))
		return mss, wsopt
	end
end

function mod.verifyAuthCookie(pkt)
	if pkt.eth.src:get() == SERVER_MAC_64 then
		--log:warn("Verify cookie from Server -> drop")
		return false
	end

	local cookie = pkt.tcp:getAckNumber()
	cookie = cookie - 1

	-- check timestamp first
	local ts = 0

	-- check hash
	local hash = band(cookie, 0x000fffff)
	if not verifyHash(
			hash, 
			pkt.ip4:getSrc(), 
			pkt.ip4:getDst(), 
			pkt.tcp:getSrc(), 
			pkt.tcp:getDst(), 
			ts
	) then
		return true
	else
		-- finally decode options and return it
		--log:debug('Received legitimate cookie')
		return true
	end
end

-------------------------------------------------------------------------------------------
---- Packet modification and crafting for cookie strategy
-------------------------------------------------------------------------------------------

-- config options
local SERVER_MSS = 1460
local SERVER_WSOPT = 7
local SERVER_TSOPT = true

-- simply resend the complete packet, but adapt seq/ack number
function mod.sequenceNumberTranslation(diff, rxBuf, txBuf, rxPkt, txPkt)
	--log:debug('Performing Sequence Number Translation ')
	-- determine direction
	local srcMac = rxPkt.eth.src
	local leftToRight = false
	if srcMac:get() == CLIENT_MAC_64 then
		leftToRight = true
	end

	local size = rxBuf:getSize() 	
	
	-- copy content
	ffi.copy(txBuf:getData(), rxBuf:getData(), size)
	txBuf:setSize(size)

	-- translate numbers, depends on direction
	-- in our setup also need to do MAC translation
	if leftToRight then
		txPkt.tcp:setAckNumber(rxPkt.tcp:getAckNumber() + diff)
		txPkt.eth.dst = SERVER_MAC
		txPkt.eth.src = PROXY_MAC_RIGHT
	else
		txPkt.tcp:setSeqNumber(rxPkt.tcp:getSeqNumber() - diff)
		txPkt.eth.dst = CLIENT_MAC
		txPkt.eth.src = PROXY_MAC_LEFT
	end

	-- reset IP checksum for offloading
	txPkt.ip4:setChecksum()
end

ffi.cdef[[
	void calculate_cookies_batched(struct rte_mbuf *pkts[], uint32_t num, struct sipkey *key);
	void calculate_auth_cookies_batched(struct rte_mbuf *pkts[], uint32_t num, struct sipkey *key);
]]

function mod.calculateCookiesBatched(mbufArray, num)
	clib.calculate_cookies_batched(mbufArray, num, hasher.key)
end

function mod.calculateAuthCookiesBatched(mbufArray, num)
	clib.calculate_auth_cookies_batched(mbufArray, num, hasher.key)
end

function mod.forwardStalled(diff, txBuf)
	--log:debug('Forwarding stalled packet')

	local txPkt = txBuf:getTcp4Packet()
	txPkt.tcp:setAckNumber(txPkt.tcp:getAckNumber() + diff)
	txPkt.eth.dst = SERVER_MAC
	txPkt.eth.src = PROXY_MAC_RIGHT
	
	-- reset IP checksum for offloading
	txPkt.ip4:setChecksum()
end

local function getTSVal(pkt)
	local offset = pkt.tcp:getDataOffset() - 5 -- options length in 32 bits (deduct 5 for standard tcp header length)
	local i = 0
	local opt = 0
	local vals = {}
	while i < offset * 4 do
		opt = pkt.payload.uint8[i]
		if opt == 8 then
			vals[1] = pkt.payload.uint8[i + 2]
			vals[2] = pkt.payload.uint8[i + 3]
			vals[3] = pkt.payload.uint8[i + 4]
			vals[4] = pkt.payload.uint8[i + 5]
			i = i + 10
			return vals
		elseif opt == 1 then
			-- nop end eol option have length 1
			i = i + 1
		elseif opt == 0 then	
			return false
		else
			-- other options
			local inc = pkt.payload.uint8[i + 1] -- increment by option length
			if inc == 0 then
				log:warn("This shouldn't happen: wrong TCP options format")
				return false
			end
			i = i + inc
		end
	end
	return false
end

function mod.createSynToServer(txBuf, rxBuf, mss, wsopt)
	-- set size of tx packet
	local size = 54
	
	-- copy data
	log:debug('copy')
	ffi.copy(txBuf:getData(), rxBuf:getData(), size)
	log:debug('copyd')
	
	-- adjust some members: sequency number, flags, checksum, length fields
	local txPkt = txBuf:getTcp4Packet()
	
	-- get timestamp value if possible
	tsVals = getTSVal(txPkt)
	
	--translate MAC
	txPkt.eth.dst = SERVER_MAC
	txPkt.eth.src = PROXY_MAC_RIGHT
	-- reduce seq num by 1 as during handshake it will be increased by 1 (in SYN/ACK)
	-- this way, it does not have to be translated at all
	txPkt.tcp:setSeqNumber(txPkt.tcp:getSeqNumber() - 1)
	txPkt.tcp:setAckNumber(0)
	txPkt.tcp:setWindow(29200)
	txPkt.tcp:setFlags(0)
	txPkt.tcp:setSyn()

	-- MSS option
	local offset = 0
	if mss then
		txPkt.payload.uint8[0] = 2 -- MSS option type
		txPkt.payload.uint8[1] = 4 -- MSS option length (4 bytes)
		txPkt.payload.uint16[1] = hton16(mss) -- MSS option
		offset = offset + 4
	end
	
	if tsVals then
		txPkt.payload.uint8[offset] = 8 -- ts option type
		txPkt.payload.uint8[offset + 1] = 10 -- ts option length (2 bytes)
		txPkt.payload.uint8[offset + 2] = tsVals[1] -- ts option tsval
		txPkt.payload.uint8[offset + 3] = tsVals[2] -- ts option tsval
		txPkt.payload.uint8[offset + 4] = tsVals[3] -- ts option tsval
		txPkt.payload.uint8[offset + 5] = tsVals[4] -- ts option tsval
		txPkt.payload.uint8[offset + 6] = 0 -- ts option ecr
		txPkt.payload.uint8[offset + 7] = 0 -- ts option ecr
		txPkt.payload.uint8[offset + 8] = 0 -- ts option ecr
		txPkt.payload.uint8[offset + 9] = 0 -- ts option ecr
		offset = offset + 10
	end
		
	-- window scale option
	if wsopt then
		txPkt.payload.uint8[offset] = 3 -- WSOPT option type
		txPkt.payload.uint8[offset + 1] = 3 -- WSOPT option length (3 bytes)
		txPkt.payload.uint8[offset + 2] = wsopt -- WSOPT option
		offset = offset + 3
	end
	
	local pad = 4 - (offset % 4)
	if pad == 4 then
		pad = 0
	end
	if pad > 0 then
		txPkt.payload.uint8[offset + pad - 1] = 0 -- eop
		for i = pad - 2, 0, -1 do
			txPkt.payload.uint8[offset + i] = 1 -- padding
		end
	end
	offset = offset + pad
	size = size + offset
	local dataOffset = 5 + (offset / 4)

	txPkt.tcp:setDataOffset(dataOffset)
	txPkt:setLength(size)
	if size < 60 then
		size = 60
	end
	txBuf:setSize(size)

	-- reset IP checksum for offloading
	txPkt.ip4:setChecksum()
end

function mod.createAckToServer(txBuf, rxBuf, rxPkt)
	-- set size of tx packet
	local size = 60
	txBuf:setSize(size)
	
	ffi.copy(txBuf:getData(), rxBuf:getData(), size)
	
	-- send packet back with seq, ack + 1
	local txPkt = txBuf:getTcp4Packet()

	-- mac addresses
	txPkt.eth.src = PROXY_MAC_RIGHT
	txPkt.eth.dst = SERVER_MAC
	
	-- ip addresses
	txPkt.ip4.src = rxPkt.ip4.dst
	txPkt.ip4.dst = rxPkt.ip4.src

	-- tcp ports
	txPkt.tcp.src = rxPkt.tcp.dst
	txPkt.tcp.dst = rxPkt.tcp.src

	txPkt.tcp.seq = rxPkt.tcp.ack
	txPkt.tcp:setAckNumber(rxPkt.tcp:getSeqNumber() + 1)
	txPkt.tcp:unsetSyn()
	txPkt.tcp:setAck()
	txPkt.tcp:setDataOffset(5)
	txPkt.tcp:setWindow(229)
	txPkt.payload.uint32[0] = 0
	txPkt.payload.uint16[2] = 0
	
	txPkt:setLength(54)

	-- reset IP checksum for offloading
	txPkt.ip4:setChecksum()
end

function mod.createSynAckToClient(txBuf, rxPkt)
	local txPkt = txBuf:getTcp4Packet()
	local cookie = calculateCookie(rxPkt)

	-- MAC addresses
	if rxPkt.eth.src:get() == CLIENT_MAC_64 then
		txPkt.eth.dst = CLIENT_MAC
	else
		txPkt.eth.dst = ATTACKER_MAC
	end
	txPkt.eth.src = PROXY_MAC_LEFT

	-- IP addresses
	txPkt.ip4.dst = rxPkt.ip4.src
	txPkt.ip4.src = rxPkt.ip4.dst
	
	-- TCP
	txPkt.tcp.src = rxPkt.tcp.dst
	txPkt.tcp.dst = rxPkt.tcp.src
	
	txPkt.tcp:setSeqNumber(cookie)
	txPkt.tcp:setAckNumber(rxPkt.tcp:getSeqNumber() + 1)

	local size = txPkt.ip4:getLength() + 14
	if size < 60 then
		size = 60
	end
	txBuf:setSize(size)
end

-- all non-TCP traffic
-- for measurement setup exchange macs and let switch do the magic
function mod.forwardTraffic(txBuf, rxBuf)
	-- set size of tx packet
	local size = rxBuf:getSize()
	txBuf:setSize(size)
	
	-- copy data 
	ffi.copy(txBuf:getData(), rxBuf:getData(), size)
	
	-- determine direction for MAC translation
	local txPkt = txBuf:getEthernetPacket()
	local srcMac = txPkt.eth.src:get()
	if srcMac == CLIENT_MAC_64 then
		txPkt.eth.dst = SERVER_MAC
		txPkt.eth.src = PROXY_MAC_RIGHT
	elseif srcMac == SERVER_MAC_64 then
		txPkt.eth.dst = CLIENT_MAC
		txPkt.eth.src = PROXY_MAC_LEFT
	end
end

-------------------------------------------------------------------------------------------
---- Packet mempools and buf arrays
-------------------------------------------------------------------------------------------

function mod.getSynAckBufs(batch)
	local lTXSynAckMem = memory.createMemPool(function(buf)
		local pkt = buf:getTcp4Packet()
		pkt:fill{
			ethSrc="90:e2:ba:98:88:e9",
			ethDst="90:e2:ba:98:58:79",
			ip4Src=SERVER_IP,
			ip4Dst="192.168.1.201",
			ip4Flags=2, -- set DF
			tcpSrc=0,
			tcpDst=0,
			tcpSeqNumber=0,
			tcpAckNumber=0,
			tcpAck=1,
			tcpSyn=1,
			tcpWindow=29200,
		}

		-- add options that the server (presumeably) supports
		local offset = 0
		-- MSS option
		if SERVER_MSS then
			pkt.payload.uint8[0] = 2 -- MSS option type
			pkt.payload.uint8[1] = 4 -- MSS option length (4 bytes)
			pkt.payload.uint16[1] = hton16(SERVER_MSS) -- MSS option
			offset = offset + 4
		end
		
		-- ts option
		if SERVER_TSOPT then
			pkt.payload.uint8[offset] = 8 -- ts option type
			pkt.payload.uint8[offset + 1] = 10 -- ts option length (2 bytes)
			pkt.payload.uint8[offset + 2] = 0 -- ts option tsval
			pkt.payload.uint8[offset + 3] = 0 -- ts option tsval
			pkt.payload.uint8[offset + 4] = 0 -- ts option tsval
			pkt.payload.uint8[offset + 5] = 0 -- ts option tsval
			pkt.payload.uint8[offset + 6] = 0 -- ts option ecr
			pkt.payload.uint8[offset + 7] = 0 -- ts option ecr
			pkt.payload.uint8[offset + 8] = 0 -- ts option ecr
			pkt.payload.uint8[offset + 9] = 0 -- ts option ecr
			offset = offset + 10
		end
		
		-- window scale option
		if SERVER_WSOPT then
			pkt.payload.uint8[offset] = 3 -- WSOPT option type
			pkt.payload.uint8[offset + 1] = 3 -- WSOPT option length (3 bytes)
			pkt.payload.uint8[offset + 2] = SERVER_WSOPT -- WSOPT option
			offset = offset + 3
		end

		-- determine if and how much padding is needed
		local pad = 4 - (offset % 4)
		if pad == 4 then
			pad = 0
		end
		if pad > 0 then
			pkt.payload.uint8[offset + pad - 1] = 0 -- eop
			for i = pad - 2, 0, -1 do
				pkt.payload.uint8[offset + i] = 1 -- padding
			end
		end
		-- calculate size and dataOffset values
		offset = offset + pad
		local size = 54 + offset -- minimum sized ip4/tcp packet with tcp options
		local dataOffset = 5 + (offset / 4)
	
		pkt.tcp:setDataOffset(dataOffset)
		pkt:setLength(size)
		if size < 60 then
			size = 60
		end
		buf:setSize(size)
	end)
	return lTXSynAckMem:bufArray(batch)
end
	
function mod.getForwardBufs(batch)
	local lTXForwardMem = memory.createMemPool(function(buf)
		local pkt = buf:getTcp4Packet():fill{
			ethSrc=proto.eth.NULL,
			ethDst=proto.eth.NULL,
			ip4Src=proto.ip4.NULL,
			ip4Dst=proto.ip4.NULL,
			tcpSrc=0,
			tcpDst=0,
			tcpSeqNumber=0,
			tcpAckNumber=0,
			tcpSyn=1,
			pktLength=60,
		}
	end)
	return lTXForwardMem:bufArray(batch)
end
	
function mod.getAckBufs(batch)
	local rTXAckMem = memory.createMemPool(function(buf)
		-- we copy RX packet anyway, so no prefilling necessary
	end)
	return rTXAckMem:bufArray(batch)
end


-------------------------------------------------------------------------------------------
---- Google Sparse Hash Map for TCP SYN cookies
-------------------------------------------------------------------------------------------

ffi.cdef [[
	struct sparse_hash_map_cookie_key {
		uint32_t ip_src;
		uint32_t ip_dst;		
		uint16_t tcp_src;
		uint16_t tcp_dst;
	};

	typedef struct sparse_hash_map_cookie_value {
		uint32_t diff;
		uint8_t flags;
		struct rte_mbuf* stalled;
	};
	
	struct sparse_hash_map_cookie {};
	struct sparse_hash_map_cookie * mg_sparse_hash_map_cookie_create(uint32_t size);
	
	void mg_sparse_hash_map_cookie_insert(struct sparse_hash_map_cookie *m, struct sparse_hash_map_cookie_key *k, uint32_t ack);
	struct sparse_hash_map_cookie_value * mg_sparse_hash_map_cookie_finalize(struct sparse_hash_map_cookie *m, struct sparse_hash_map_cookie_key *k, uint32_t seq);
	struct sparse_hash_map_cookie_value * mg_sparse_hash_map_cookie_find_update(struct sparse_hash_map_cookie *m, struct sparse_hash_map_cookie_key *k, bool reset, bool left_fin, bool right_fin, bool ack);
]]

local sparseHashMapCookie = {}
sparseHashMapCookie.__index = sparseHashMapCookie

function mod.createSparseHashMapCookie(size)
	log:info("Creating a sparse hash map for TCP SYN flood cookie strategy")
	return setmetatable({
		map = clib.mg_sparse_hash_map_cookie_create(size or 0)
	}, sparseHashMapCookie)
end


local key = ffi.new("struct sparse_hash_map_cookie_key")
local function sparseHashMapCookieGetKey(pkt, leftToRight)
	if leftToRight then
		key.ip_src = pkt.ip4:getSrc()
		key.ip_dst = pkt.ip4:getDst()
		key.tcp_src = pkt.tcp:getSrc()
		key.tcp_dst = pkt.tcp:getDst()
	else
		key.ip_src = pkt.ip4:getDst()
		key.ip_dst = pkt.ip4:getSrc()
		key.tcp_src = pkt.tcp:getDst()
		key.tcp_dst = pkt.tcp:getSrc()
	end
	--log:debug("Key: " .. key.ip_src .. ":" .. key.tcp_src .. "->" .. key.ip_dst .. ":" .. key.tcp_dst)
	return key
end

function sparseHashMapCookie:setLeftVerified(pkt)
	--log:debug("set left verified")
	local k = sparseHashMapCookieGetKey(pkt, true)
	local ack = pkt.tcp:getAckNumber()
	clib.mg_sparse_hash_map_cookie_insert(self.map, k, ack)
end

function sparseHashMapCookie:setRightVerified(pkt)
	--log:debug("set right verified")
	local k = sparseHashMapCookieGetKey(pkt, false)
	local seq = pkt.tcp:getSeqNumber()
	local diff = clib.mg_sparse_hash_map_cookie_finalize(self.map, k, seq)

	if not (diff == nil) then
		if band(diff.flags, 64) and not (diff.stalled == nil) then
			local stalledPointer = diff.stalled
			diff.stalled = nil -- unset it, we sent it after all and dont need to free manually
			diff.flags = band(diff.flags, bnot(64)) -- unset the flag
			return diff.diff, stalledPointer
		else
			return diff.diff
		end
	else
		-- not left verified,
		-- happens if a connection is deleted 
		-- but right still has some packets in flight
		-- or packets are sent duplicated
		--log:debug('Not left verified, something is wrong')
		--log:debug("no result")
		return false
	end
end

function sparseHashMapCookie:isVerified(pkt)
	local leftToRight = false
	if pkt.ip4:getDst() == SERVER_IP then
		leftToRight = true
	end

	local reset = false
	local leftFin = false
	local rightFin = false
	local ack = false
	if pkt.tcp:getRst() then
		reset = true
	end
	if pkt.tcp:getFin() then
		if leftToRight then
			leftFin = true
		else
			rightFin = true
		end
	end
	if pkt.tcp:getAck() then
		ack = true
	end

	local k = sparseHashMapCookieGetKey(pkt, leftToRight)

	local diff = clib.mg_sparse_hash_map_cookie_find_update(self.map, k, reset, leftFin, rightFin, ack)
	if not (diff == nil) then
		if band(diff.flags, 64) == 64 and diff.stalled == nil then
			return "stall", diff
		end
		return diff.diff
	else
		return false
	end
end

return mod
