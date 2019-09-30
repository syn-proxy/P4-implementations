---------------------------------
--- @file synAuthentication.lua
--- @brief TCP SYN flood mitigation via SYN authentication
--- Includes:
--- - wrong Ack number on initial SYN
---------------------------------

local ffi 	= require "ffi"
local log	= require "log"
local memory = require "memory"
local proto = require "proto/proto"
local cookie = require "src/synCookie"
local verifyAuthCookie = cookie.verifyAuthCookie
require "utils"

local clib = ffi.load("build/proxy")

local mod = {}


-------------------------------------------------------------------------------------------
---- Packet modification and crafting for SYN authentication
-------------------------------------------------------------------------------------------

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

function mod.forwardTraffic(txBuf, rxBuf)
	cookie.forwardTraffic(txBuf, rxBuf)
end

local function setSwappedAddresses(txPkt, rxPkt)
	-- MAC addresses
	txPkt.eth:setSrc(rxPkt.eth:getDst())
	txPkt.eth:setDst(rxPkt.eth:getSrc())

	-- IP addresses
	txPkt.ip4:setSrc(rxPkt.ip4:getDst())
	txPkt.ip4:setDst(rxPkt.ip4:getSrc())
	
	-- TCP
	txPkt.tcp:setSrc(rxPkt.tcp:getDst())
	txPkt.tcp:setDst(rxPkt.tcp:getSrc())
end

function mod.createResponseAuthInvalid(txBuf, rxPkt)
	local txPkt = txBuf:getTcp4Packet()

	setSwappedAddresses(txPkt, rxPkt)

	-- set violating ack number
	txPkt.tcp:setAckNumber(rxPkt.tcp:getSeqNumber() - 1) 
	-- violation => AckNumber != SeqNumber + 1
end

function mod.createResponseRst(txBuf, rxPkt)
	local txPkt = txBuf:getTcp4Packet()
	
	setSwappedAddresses(txPkt, rxPkt)

	txPkt.tcp:setSeqNumber(rxPkt.tcp:getAckNumber())
	-- ack is irrelevant
end

function mod.createResponseAuthFull(txBuf, rxPkt)
	local txPkt = txBuf:getTcp4Packet()
	
	setSwappedAddresses(txPkt, rxPkt)

	txPkt.tcp:setAckNumber(rxPkt.tcp:getSeqNumber() + 1)
	-- we choose seq number
end

function mod.createResponseAuthCookie(txBuf, rxPkt)
	local txPkt = txBuf:getTcp4Packet()
	
	setSwappedAddresses(txPkt, rxPkt)

	txPkt.tcp:setAckNumber(rxPkt.tcp:getSeqNumber() + 1)
	-- we choose seq number for batch
end

function mod.getSynAckBufs(batch)
	local mem = memory.createMemPool(function(buf)
		local pkt = buf:getTcp4Packet():fill{
			ethSrc=proto.eth.NULL,
			ethDst=proto.eth.NULL,
			ip4Src=proto.ip4.NULL,
			ip4Dst=proto.ip4.NULL,
			tcpSrc=0,
			tcpDst=0,
			tcpSeqNumber=42, -- randomly chosen
			tcpAckNumber=0,  -- set depending on RX
			tcpSyn=1,
			tcpAck=1,
			pktLength=54,
		}
	end)
	return mem:bufArray(batch)
end

function mod.getRstBufs(batch)
	local mem = memory.createMemPool(function(buf)
		local pkt = buf:getTcp4Packet():fill{
			ethSrc=proto.eth.NULL,
			ethDst=proto.eth.NULL,
			ip4Src=proto.ip4.NULL,
			ip4Dst=proto.ip4.NULL,
			tcpSrc=0,
			tcpDst=0,
			tcpSeqNumber=0,
			tcpAckNumber=0,
			tcpRst=1,
			pktLength=60,
		}
	end)
	return mem:bufArray(batch)
end


----------------------------------------------------------------------------------------------------------------------------
---- Bit map for syn authentication (invalid|full)
----------------------------------------------------------------------------------------------------------------------------

ffi.cdef [[
	struct bit_map_auth_map {};
	struct bit_map_auth_map * mg_bit_map_auth_create();
	
	bool mg_bit_map_auth_update(struct bit_map_auth_map *m, uint32_t k, bool forced);
	bool mg_bit_map_auth_update_syn(struct bit_map_auth_map *m, uint32_t k);
]]

local bitMapAuth = {}
bitMapAuth.__index = bitMapAuth

function mod.createBitMapAuth()
	log:info("Creating a bit map for TCP SYN Authentication strategy")
	return setmetatable({
		map = clib.mg_bit_map_auth_create()
	}, bitMapAuth)
end

local function getKey(pkt)
	local mac = pkt.eth.src
	if mac:get() == CLIENT_MAC_64 then
		return pkt.ip4:getSrc()
	else
		return pkt.ip4:getDst()
	end
end

function bitMapAuth:isWhitelisted(pkt)
	local k = getKey(pkt)
	return clib.mg_bit_map_auth_update(self.map, k, pkt.tcp:getRst())
end

function bitMapAuth:isWhitelistedFull(pkt)
	local k = getKey(pkt)
	local isAck = pkt.tcp:getAck() and not pkt.tcp:getSyn()
	if isAck then
		local verified = verifyAuthCookie(pkt)
		if verified == false then
			return 0
		end
	end
	local result = clib.mg_bit_map_auth_update(self.map, k, isAck)
	if result then
		return 1 -- forward
	elseif isAck then
		return 2 -- reply with rst
	else
		return 0 -- drop
	end
end

function bitMapAuth:isWhitelistedSyn(pkt)
	local k = getKey(pkt)
	return clib.mg_bit_map_auth_update_syn(self.map, k)
end


----------------------------------------------------------------------------------------------------------------------------
---- Bit map for syn authentication TTL
----------------------------------------------------------------------------------------------------------------------------

ffi.cdef [[
	struct bit_map_auth_ttl_map {};
	struct bit_map_auth_ttl_map * mg_bit_map_auth_ttl_create();
	
	bool mg_bit_map_auth_ttl_update(struct bit_map_auth_ttl_map *m, uint32_t k, bool forced, uint8_t ttl, uint8_t range);
	bool mg_bit_map_auth_ttl_update_syn(struct bit_map_auth_ttl_map *m, uint32_t k, uint8_t ttl);
]]

local bitMapAuthTtl = {}
bitMapAuthTtl.__index = bitMapAuthTtl

function mod.createBitMapAuthTtl()
	log:info("Creating a bit map for TCP SYN Authentication TTL strategy")
	return setmetatable({
		map = clib.mg_bit_map_auth_ttl_create()
	}, bitMapAuthTtl)
end

local RANGE = 0

function bitMapAuthTtl:isWhitelisted(pkt)
	local k = getKey(pkt)
	return clib.mg_bit_map_auth_ttl_update(self.map, k, pkt.tcp:getRst(), pkt.ip4:getTTL(), RANGE)
end

function bitMapAuthTtl:isWhitelistedSyn(pkt)
	local k = getKey(pkt)
	return clib.mg_bit_map_auth_ttl_update_syn(self.map, k, pkt.ip4:getTTL())
end


return mod
