local libmoon	= require "libmoon"
local memory	= require "memory"
local device	= require "device"
local stats		= require "stats"
local log		= require "log"
local ffi		= require "ffi"
local proto		= require "proto/proto"
local check		= require "proto/packetChecks"

-- tcp SYN defense strategies
local cookie	= require "src/synCookie"
local auth		= require "src/synAuthentication"

-- Adjust luajit parameters
local jit = require "jit"
jit.opt.start("maxrecord=10000", "maxirconst=1000", "loopunroll=40")

-- implemented strategies
local STRAT = {
	cookie 		= 1,
	auth_invalid= 2,
	auth_full	= 3,
	auth_ttl	= 4,
	auth_cookie	= 5,
}

function configure(parser)
	parser:description("TCP SYN Proxy")
	parser:argument("devL", "Left device to use"):args(1):convert(tonumber)
	parser:argument("devR", "Right device to use"):args(1):convert(tonumber)
	strats = ""
	first = true
	for k,_ in pairs(STRAT) do
		if first then
			strats = k
			first = false
		else
			strats = strats .. "|" .. k
		end
	end
	parser:option("-s --strategy", "Mitigation strategy [" .. strats .. "]"):args("1"):convert(STRAT):default('cookie')
	parser:option("-t --threads", "Number of threads to start"):args(1):convert(tonumber):default(1)
	parser:option("-b --batch", "Batchsize"):args(1):convert(tonumber):default(63)
	return parser:parse()
end

function master(args, ...)
	local devL = device.config{ 
		port = args.devL ,
		txQueues = args.threads,
		rxQueues = args.threads,
		rssQueues = args.threads
	}
	local devR = device.config{ 
		port = args.devR ,
		txQueues = args.threads,
		rxQueues = args.threads,
		rssQueues = args.threads
	}
	device.waitForLinks()

	for i = 1, args.threads do
		libmoon.startTask("synProxyTask", devL, devR, args.strategy, i - 1, args.batch)
	end
	stats.startStatsTask{devL, devR} 
	libmoon.waitForTasks()
end


----------------------------------------------------
-- check packet type
----------------------------------------------------

local isIP4 	= check.isIP4
local isTcp4 	= check.isTcp4


-------------------------------------------------------------------------------------------
---- Cookie
-------------------------------------------------------------------------------------------

local verifyCookie 				= cookie.verifyCookie
local sequenceNumberTranslation = cookie.sequenceNumberTranslation
local createSynAckToClient 		= cookie.createSynAckToClient
local createSynToServer 		= cookie.createSynToServer
local createAckToServer 		= cookie.createAckToServer
local forwardTraffic 			= cookie.forwardTraffic
local forwardStalled 			= cookie.forwardStalled
local calculateCookiesBatched 	= cookie.calculateCookiesBatched


-------------------------------------------------------------------------------------------
---- Syn Auth
-------------------------------------------------------------------------------------------

local forwardTrafficAuth 		= auth.forwardTraffic
local createResponseAuthInvalid	= auth.createResponseAuthInvalid
local createResponseAuthFull 	= auth.createResponseAuthFull
local createResponseAuthCookie 	= auth.createResponseAuthCookie
local createResponseRst 		= auth.createResponseRst
local createResponseCookie 		= auth.createResponseCookie
local calculateAuthCookiesBatched 	= cookie.calculateAuthCookiesBatched


---------------------------------------------------
-- task
---------------------------------------------------

local function info(msg, id)
	print(getColorCode(id + 1) .. '[proxy: id=' .. id .. '] ' .. getColorCode("white") .. msg)
end

function synProxyTask(devL, devR, strategy, threadId, batch)
	--log:setLevel("DEBUG")
	info('Initialising SYN proxy', threadId)

	local maxBurstSize = batch

	-- RX buffers for left
	local lRXQueue = devL:getRxQueue(threadId)
	local lRXMem = memory.createMemPool()	
	local lRXBufs = lRXMem:bufArray(maxBurstSize)

	-- RX buffers for right
	local rRXQueue = devR:getRxQueue(threadId)
	local rRXMem = memory.createMemPool()	
	local rRXBufs = rRXMem:bufArray(maxBurstSize)

	-- TX buffers
	local lTXQueue = devL:getTxQueue(threadId)
	local rTXQueue = devR:getTxQueue(threadId)

	-- buffer for cookie syn/ack to left
	local numSynAck = 0
	local lTXSynAckBufs = cookie.getSynAckBufs(maxBurstSize)
	
	-- ack to right (on syn/ack from right)
	local numAck = 0
	local rTXAckBufs = cookie.getAckBufs(maxBurstSize)
	
	-- buffer for forwarding
	local numForwardL = 0 
	local lTXForwardBufs = cookie.getForwardBufs(maxBurstSize)
	local numForwardR = 0 
	local rTXForwardBufs = cookie.getForwardBufs(maxBurstSize)
	
	-- buffer for syn auth answer to left
	local numAuth = 0
	local lTXAuthBufs = auth.getSynAckBufs(maxBurstSize)
	
	-- buffer for rst answer to left
	local numRst = 0
	local lTXRstBufs = auth.getRstBufs(maxBurstSize)

	-- buffers for not TCP packets
	-- need to behandled separately as we cant just offload TCP checksums here
	-- its only a few packets anyway, so handle them separately
	local txNotTcpMem = memory.createMemPool()	
	local txNotTcpBufs = txNotTcpMem:bufArray(1)


	-------------------------------------------------------------
	-- State keeping data structure
	-------------------------------------------------------------
	local stateCookie
	local bitMapAuth
	local bitMapAuthTtl
	if strategy == STRAT['cookie'] then
		stateCookie = cookie.createSparseHashMapCookie()
	elseif strategy == STRAT['auth_ttl'] then
		bitMapAuthTtl = auth.createBitMapAuthTtl()
	else
		bitMapAuth = auth.createBitMapAuth()
	end
	

	-------------------------------------------------------------
	-- mempool and buffer to store stalled segments
	-------------------------------------------------------------
	local stallMem = memory.createMemPool()
	local stallBufs = stallMem:bufArray(1)


	-------------------------------------------------------------
	-- main event loop
	-------------------------------------------------------------
	info('Starting SYN proxy using ' .. strategy, threadId)
	--log:debug('strting')
	while libmoon.running() do
		-- LEFT side processing
		rx = lRXQueue:tryRecv(lRXBufs, 1)
		numSynAck = 0
		numAck = 0
		numForwardL = 0
		numForwardR = 0
		numAuth = 0
		for i = 1, rx do
			local lRXPkt = lRXBufs[i]:getTcp4Packet()
			--lRXBufs[i]:dump()
			if not isTcp4(lRXPkt) then
				--log:debug('Sending packet that is not TCP from left')
				txNotTcpBufs:alloc(60)
				forwardTraffic(txNotTcpBufs[1], lRXBufs[i])
				rTXQueue:sendN(txNotTcpBufs, 1)
			else -- TCP
				--lRXBufs[i]:dump()
				-- TCP SYN Authentication strategy
				if strategy == STRAT['auth_invalid'] then
					-- send wrong acknowledgement number on unverified SYN
					local forward = false
					if lRXPkt.tcp:getSyn() and not lRXPkt.tcp:getAck() then
						if bitMapAuth:isWhitelistedSyn(lRXPkt) then
							forward = true
						else
							-- create and send packet with wrong sequence number
							if numAuth == 0 then
								lTXAuthBufs:allocN(60, rx - (i - 1))
							end
							numAuth = numAuth + 1
							createResponseAuthInvalid(lTXAuthBufs[numAuth], lRXPkt)
						end
					else
						if bitMapAuth:isWhitelisted(lRXPkt) then
							forward = true
						else
							-- drop
							-- we either received a rst that now whitelisted the connection
							-- or we received not whitelisted junk
						end
					end
					if forward then
						if numForwardR == 0 then
							rTXForwardBufs:allocN(60, rx - (i - 1))
						end
						numForwardR = numForwardR + 1
						forwardTrafficAuth(rTXForwardBufs[numForwardR], lRXBufs[i])
					end
				elseif strategy == STRAT['auth_full'] then
					-- do a full handshake for whitelisting, then proxy sends rst
					local forward = false
					if lRXPkt.tcp:getSyn() and not lRXPkt.tcp:getAck() then
						if bitMapAuth:isWhitelistedSyn(lRXPkt) then
							forward = true
						else
							-- create and send packet with wrong sequence number
							if numAuth == 0 then
								lTXAuthBufs:allocN(60, rx - (i - 1))
							end
							numAuth = numAuth + 1
							createResponseAuthFull(lTXAuthBufs[numAuth], lRXPkt)
						end
					else
						local action = bitMapAuth:isWhitelistedFull(lRXPkt) 
						if action == 1 then
							forward = true
						elseif action == 2 then
							-- send rst
							if numRst == 0 then
								lTXRstBufs:allocN(60, rx - (i - 1))
							end
							numRst = numRst + 1
							createResponseRst(lTXRstBufs[numRst], lRXPkt)
						else
							-- drop
							-- we either received a rst that now whitelisted the connection
							-- or we received not whitelisted junk
						end
					end
					if forward then
						if numForwardR == 0 then
							rTXForwardBufs:allocN(60, rx - (i - 1))
						end
						numForwardR = numForwardR + 1
						forwardTrafficAuth(rTXForwardBufs[numForwardR], lRXBufs[i])
					end
				elseif strategy == STRAT['auth_cookie'] then
					-- do a full handshake with cookie for whitelisting, then proxy sends rst
					local forward = false
					if lRXPkt.tcp:getSyn() and not lRXPkt.tcp:getAck() then
						if bitMapAuth:isWhitelistedSyn(lRXPkt) then
							forward = true
						else
							-- create and send packet with wrong sequence number
							if numAuth == 0 then
								lTXAuthBufs:allocN(60, rx - (i - 1))
							end
							numAuth = numAuth + 1
							createResponseAuthCookie(lTXAuthBufs[numAuth], lRXPkt)
						end
					else
						local action = bitMapAuth:isWhitelistedFull(lRXPkt) 
						if action == 1 then
							forward = true
						elseif action == 2 then
							-- send rst
							if numRst == 0 then
								lTXRstBufs:allocN(60, rx - (i - 1))
							end
							numRst = numRst + 1
							createResponseRst(lTXRstBufs[numRst], lRXPkt)
						else
							-- drop
							-- we either received a rst that now whitelisted the connection
							-- or we received not whitelisted junk
						end
					end
					if forward then
						if numForwardR == 0 then
							rTXForwardBufs:allocN(60, rx - (i - 1))
						end
						numForwardR = numForwardR + 1
						forwardTrafficAuth(rTXForwardBufs[numForwardR], lRXBufs[i])
					end
				elseif strategy == STRAT['auth_ttl'] then
					-- send wrong acknowledgement number on unverified SYN
					-- only accept the RST from the client if the TTL values match
					local forward = false
					if lRXPkt.tcp:getSyn() and not lRXPkt.tcp:getAck() then
						if bitMapAuthTtl:isWhitelistedSyn(lRXPkt) then
							forward = true
						else
							-- create and send packet with wrong sequence number
							if numAuth == 0 then
								lTXAuthBufs:allocN(60, rx - (i - 1))
							end
							numAuth = numAuth + 1
							createResponseAuthInvalid(lTXAuthBufs[numAuth], lRXPkt)
						end
					else
						if bitMapAuthTtl:isWhitelisted(lRXPkt) then
							forward = true
						else
							-- drop
							-- we either received a rst that now whitelisted the connection
							-- or we received not whitelisted junk
						end
					end
					if forward then
						if numForwardR == 0 then
							rTXForwardBufs:allocN(60, rx - (i - 1))
						end
						numForwardR = numForwardR + 1
						forwardTrafficAuth(rTXForwardBufs[numForwardR], lRXBufs[i])
					end
				else
				-- TCP SYN Cookie strategy
					if lRXPkt.tcp:getSyn() then
						if not lRXPkt.tcp:getAck() then -- SYN -> send SYN/ACK
							--log:debug('Received SYN from left')
							if numSynAck == 0 then
								lTXSynAckBufs:allocN(60, rx - (i - 1))
							end
							numSynAck = numSynAck + 1
							createSynAckToClient(lTXSynAckBufs[numSynAck], lRXPkt)
						else
							--log:debug("ignore syn/ack from left")
						end
					else -- check verified status
						local diff, stalled = stateCookie:isVerified(lRXPkt) 
						if not diff and lRXPkt.tcp:getAck() then -- finish handshake with left, start with right
							--log:debug("verifying cookie")
							local mss, wsopt = verifyCookie(lRXPkt)
							if mss then
								--log:debug('Received valid cookie from left, starting handshake with server')
								
								stateCookie:setLeftVerified(lRXPkt)
								-- connection is left verified, start handshake with right
								if numForwardR == 0 then
									rTXForwardBufs:allocN(60, rx - (i - 1))
								end
								numForwardR = numForwardR + 1
								createSynToServer(rTXForwardBufs[numForwardR], lRXBufs[i], mss, wsopt)
							else
								--log:warn('Wrong cookie, dropping packet ')
								-- drop, and done
								-- most likely simply the timestamp timed out
								-- but it might also be a DoS attack that tried to guess the cookie
							end
						elseif not diff then
							-- not verified, not ack -> drop
							--log:warn("dropping unverfied not ack packet from left")
						elseif diff == "stall" then
							stallBufs:allocN(60, 1)
							ffi.copy(stallBufs[1]:getData(), lRXBufs[i]:getData(), lRXBufs[i]:getSize())
							stallBufs[1]:setSize(lRXBufs[i]:getSize())
							stalled.stalled = stallBufs[1]
						elseif diff then 
							--log:debug('Received packet of verified connection from left, translating and forwarding')
							if numForwardR == 0 then
								rTXForwardBufs:allocN(60, rx - (i - 1))
							end
							numForwardR = numForwardR + 1
							sequenceNumberTranslation(diff, lRXBufs[i], rTXForwardBufs[numForwardR], lRXPkt, rTXForwardBufs[numForwardR]:getTcp4Packet())
						else
							-- should not happen
							log:error('unhandled packet ' )
						end
					end
				end
			end
		end
		if rx > 0 then
			-- strategy specific responses
			if strategy == STRAT['cookie'] then	
				if numSynAck > 0 then
					-- send syn ack
					calculateCookiesBatched(lTXSynAckBufs.array, numSynAck)
					lTXSynAckBufs:offloadTcpChecksums(nil, nil, nil, numSynAck)
					lTXQueue:sendN(lTXSynAckBufs, numSynAck)
					lTXSynAckBufs:freeAfter(numSynAck)
				end
			elseif strategy == STRAT['auth_cookie'] then	
				if numAuth > 0 then
					-- send syn ack
					calculateAuthCookiesBatched(lTXAuthBufs.array, numAuth)
					lTXAuthBufs:offloadTcpChecksums(nil, nil, nil, numAuth)
					lTXQueue:sendN(lTXAuthBufs, numAuth)
					lTXAuthBufs:freeAfter(numAuth)
				end
			else
				-- send packets with wrong ack number
				if numAuth > 0 then
					lTXAuthBufs:offloadTcpChecksums(nil, nil, nil, numAuth)
					lTXQueue:sendN(lTXAuthBufs, numAuth)
					lTXAuthBufs:freeAfter(numAuth)
				end
			end
			-- all strategies
			-- send forwarded packets and free unused buffers
			if numForwardR > 0 then
				-- authentication strategies dont touch anything above ethernet
				-- offloading would set checksums to 0 -> dont
				if strategy == STRAT['cookie'] then
					rTXForwardBufs:offloadTcpChecksums(nil, nil, nil, numForwardR)
				end
				--for a = 1, numForwardR do
				--	rTXForwardBufs[a]:dump()
				--end
				rTXQueue:sendN(rTXForwardBufs, numForwardR)
				rTXForwardBufs:freeAfter(numForwardR)
			end
			
			-- no rx packets reused --> free
			lRXBufs:freeAll(rx)
		end

		-- RIGHT side processing
		rx = rRXQueue:tryRecv(rRXBufs, 1)
		for i = 1, rx do
			local rRXPkt = rRXBufs[i]:getTcp4Packet()
			--lRXBufs[i]:dump()
			if not isTcp4(rRXPkt) then
				--log:debug('Sending packet that is not TCP')
				txNotTcpBufs:alloc(60)
				forwardTraffic(txNotTcpBufs[1], rRXBufs[i])
				lTXQueue:sendN(txNotTcpBufs, 1)
			else -- TCP
				--lRXBufs[i]:dump()
				-- TCP SYN Authentication strategy -> forward
				if strategy == STRAT['auth_invalid'] or strategy == STRAT['auth_full'] or strategy == STRAT['auth_ttl'] or strategy == STRAT['auth_cookie'] then
					if numForwardL == 0 then
						lTXForwardBufs:allocN(60, rx - (i - 1))
					end
					numForwardL = numForwardL + 1
					forwardTrafficAuth(lTXForwardBufs[numForwardL], rRXBufs[i])
				else
				-- TCP SYN Cookie strategy
					if rRXPkt.tcp:getSyn() then
						if not rRXPkt.tcp:getAck() then -- SYN -> ignore
							--log:debug('Ignore SYN from right')
						else -- SYN/ACK from right -> send ack + stall table lookup
							--log:debug('Received SYN/ACK from server, sending ACK back')
							local diff, stalled = stateCookie:setRightVerified(rRXPkt)
							if diff then
								-- ack to server
								rTXAckBufs:allocN(60, 1)
								createAckToServer(rTXAckBufs[1], rRXBufs[i], rRXPkt)
								rTXAckBufs[1]:offloadTcpChecksum()
								rTXQueue:sendSingle(rTXAckBufs[1])
									
								if stalled then
									--log:debug('sending stalled')
									forwardStalled(diff, stalled)
									stalled:offloadTcpChecksum()
									rTXQueue:sendSingle(stalled)
								end
							else
								--log:debug("right verify failed")
							end
						end
					-- any verified packet from server
					else -- check verified status
						local diff, stalled = stateCookie:isVerified(rRXPkt) 
						if not diff then
							-- not verified, not syn/ack from right
							--log:warn("dropping unverfied not syn packet from right")
						elseif diff == "stall" then
							--log:debug('stall from right')
						elseif diff then 
							--log:debug('Received packet of verified connection from right, translating and forwarding')
							if numForwardL == 0 then
								lTXForwardBufs:allocN(60, rx - (i - 1))
							end
							numForwardL = numForwardL + 1
							sequenceNumberTranslation(diff, rRXBufs[i], lTXForwardBufs[numForwardL], rRXPkt, lTXForwardBufs[numForwardL]:getTcp4Packet())
						else
							-- should not happen
							log:error('unhandled packet right' )
						end
					end
				end
			end
		end
		if rx > 0 then
			-- all strategies
			-- send forwarded packets and free unused buffers
			if numForwardL > 0 then
				-- authentication strategies dont touch anything above ethernet
				-- offloading would set checksums to 0 -> dont
				if strategy == STRAT['cookie'] then
					lTXForwardBufs:offloadTcpChecksums(nil, nil, nil, numForwardL)
				end
				lTXQueue:sendN(lTXForwardBufs, numForwardL)
				lTXForwardBufs:freeAfter(numForwardL)
			end
			
			-- no rx packets reused --> free
			rRXBufs:freeAll(rx)
		end
	end
	info('Finished SYN proxy', threadId)
end
