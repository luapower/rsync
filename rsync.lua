--go@ x:/luapower/bin/mingw64/luajit "rsync.lua"

--rsync algorithm in Lua.
--Written by Cosmin Apreutesei. Public Domain.

local ffi = require'ffi'
local bit = require'bit'
local ringbuffer = require'ringbuffer'
local shl, shr, bor, band = bit.lshift, bit.rshift, bit.bor, bit.band

local DEFAULT_BLOCK_LEN = 1024

--rolling sum algorithm

local R = 31 --keep this a prime number

local rollsum = ffi.typeof[[
struct {
	uint32_t count; /* count of bytes included in sum */
	uint32_t s1;    /* s1 part of sum */
	uint32_t s2;    /* s2 part of sum */
}
]]

local rs = {}
rs.__index = rs

function rs.reset(sum)
	ffi.fill(sum, ffi.sizeof(sum))
end

function rs.rotate(sum, outc, inc)
	sum.s1 = sum.s1 + (inc - outc)
	sum.s2 = sum.s2 + sum.s1 - sum.count * (outc + R)
end

function rs.rollin(sum, c)
	sum.s1 = sum.s1 + (c + R)
	sum.s2 = sum.s2 + sum.count * (c + R)
	sum.count = sum.count + 1
end

function rs.rollout(sum, c)
	sum.s1 = sum.s1 - (c + R)
	sum.s2 = sum.s2 - sum.count * (c + R)
	sum.count = sum.count - 1
end

function rs.final(sum)
	return bor(shl(sum.s2, 16), band(sum.s1, 0xffff))
end

function rs.update(sum, buf, len)
	local s1 = ffi.cast('uint32_t', sum.s1)
	local s2 = ffi.cast('uint32_t', sum.s2)
	sum.count = sum.count + len
	for i = 0, len-1 do
		s1 = s1 + buf[i] + R
		s2 = s2 + s1
	end
	sum.s1 = s1
	sum.s2 = s2
end

ffi.metatype(rollsum, rs)

--generate weak and strong signatures for all the blocks of a stream.
local function gen_signatures(read_file, write_sig, weak_sum, strong_sum, block_len)
	local block_len = block_len or DEFAULT_BLOCK_LEN
	local d1 = weak_sum()
	local d2 = strong_sum()
	local buf = ffi.new('uint8_t[?]', block_len)
	while true do
		local len = assert(read_file(buf, block_len))
		if len == 0 then break end
		d1:reset()
		d2:reset()
		d1:update(buf, len)
		d2:update(buf, len)
		write_sig(d1:final(), d2:final())
	end
end

--replace `write_cmd(cmd, ...)` such that consecutive 'copy' blocks are merged.
local function copy_cmd_merger(write_cmd)
	local cmd0, ofs0, len0
	return function(cmd, ...)
		if cmd == 'copy' then
			local ofs, len = ...
			if cmd0 == 'copy' then --consecutive copy command
				if ofs == ofs0 + len0 then --consecutive block, merge it
					len0 = len0 + len
				else --non-consecutive block
					write_cmd('copy', ofs0, len0) --flush pending command
					ofs0, len0 = ofs, len --replace pending command with this one
				end
			else --first copy command
				ofs0, len0 = ofs, len --start pending command
			end
		else --unknown command
			if cmd0 == 'copy' then
				write_cmd('copy', ofs0, len0) --flush pending command
			end
			write_cmd(cmd, ...) --pass-through
		end
		cmd0 = cmd
	end
end

--generate deltas for a stream and a list of strong+weak signature pairs
local function gen_delta(read_file, read_sigs, write_cmd,
	weak_sum, strong_sum, block_len, databufsize)

	local block_len = block_len or DEFAULT_BLOCK_LEN

	local t1 = {} --{sig1 -> true}
	local t2 = {} --{sig2 -> offset}
	local offset = 0
	for sig1, sig2 in read_sigs do
		t1[sig1] = true
		t2[sig2] = offset
		offset = offset + block_len
	end

	local rb = ringbuffer{size = block_len, ctype = 'uint8_t'}
	local d1 = weak_sum()
	local d2 = strong_sum()
	local write_cmd = copy_cmd_merger(write_cmd, block_len)

	local hashed, byte1

	local databuf = ffi.new('uint8_t[?]', databufsize)
	local dataofs = 0

	local function flush_data()
		write_cmd('data', databuf, dataofs)
		dataofs = 0
	end

	local function append_byte(byte)
		if dataofs == databufsize then
			flush_data()
		end
		databuf[dataofs] = byte
		dataofs = dataofs + 1
	end

	local function check_rb() --rb is either full or containing the last segment
		if not hashed then
			d1:reset()
			local i1, n1, i2, n2 = rb:segments()
			d1:update(rb.data + i1, n1)
			if n2 > 0 then
				d1:update(rb.data + i2, n2)
			end
			hashed = true
		else
			local byte2 = rb.data[rb:tail(-1)]
			d1:rotate(byte1, byte2)
		end
		local sig1 = d1:final()
		local v = t1[sig1]
		if v then
			d2:reset()
			local i1, n1, i2, n2 = rb:segments()
			d2:update(rb.data + i1, n1)
			if n2 > 0 then
				d2:update(rb.data + i2, n2)
			end
			local sig2 = d2:final()
			local offset1 = t2[sig2]
			if offset1 then
				if byte1 then
					flush_data()
					byte1 = nil
				end
				write_cmd('copy', offset1, rb.length)
				rb:pull(rb.length)
				hashed = nil
				return
			end
		end
		if byte1 then
			append_byte(byte1)
		end
		local i = rb:pull(1)
		byte1 = rb.data[i]
	end

	local buf = ffi.new('uint8_t[?]', block_len)
	while true do
		local len = assert(read_file(buf, block_len))
		if len == 0 then break end
		while len > 0 do
			local pushlen = math.min(len, rb.size - rb.length)
			if pushlen > 0 then
				rb:push(pushlen, buf)
			end
			if rb.size - rb.length == 0 then
				check_rb()
			end
			len = len - pushlen
			buf = buf + pushlen
		end
	end
	while rb.length > 0 do
		check_rb()
	end
	write_cmd'end'
end

--serialization and deserialization of signatures, deltas and patching.

local pass = function(x) return x end
local bswap32 = ffi.abi'le' and pass or bit.bswap
local bswap16 = ffi.abi'le' and pass or function(x)
	local lo = band(x, 0xff)
	local hi = shr(x, 8)
	return lo * 0xff + hi
end
local bswap64 = ffi.abi'le' and pass or function(x)

end

local function sig_serializer(write_file, sig2_len)
	local ibuf = ffi.new'int32_t[1]'
	return function(sig1, sig2)
		ibuf[0] = bswap(sig1)
		write_file(ffi.cast('const char*', ibuf), 4)
		write_file(ffi.cast('const char*', sig2), sig2_len)
	end
end

local function sig_loader(read_file, sig2_len)
	local ibuf = ffi.new'int32_t[1]'
	local sbuf = ffi.new('uint8_t[?]', sig2_len)
	return function()
		assert(read_file(ibuf, 4) == 4)
		local sig1 = bswap(ibuf[0])
		assert(read_file(sbuf, sig2_len) == sig2_len)
		local sig2 = ffi.string(sbuf, sig2_len)
		return sig1, sig2
	end
end

local delta_ct = ffi.typeof[[struct __attribute__((__packed__)) {
	int8_t cmd;
	uint16_t len;
	uint64_t offset;
}]]
local function delta_serializer(write_file)
	local cbuf = delta_ct()
	return function(cmd, ...)
		if cmd == 'data' then
			local buf, len = ...
			cbuf.cmd = 0
			cbuf.len = bswap16(len)
			write_file(cbuf, 1+2)
		elseif cmd == 'copy' then
			local ofs, len = ...
			cbuf.cmd = 1
			cbuf.len = bswap16(len)
			cbuf.offset = bswap64(ofs)
			write_file(cbuf, 1+2+8)
		end
	end
end

local function delta_loader(read_file, write_cmd)
	local cbuf = delta_ct()
	local p = ffi.cast('char*', cbuf)+1
	local dbuf = ffi.new('uint8_t[?]', 2^16)
	assert(read_file(p, 2+8) == 2+8)
	assert(read_file(cbuf, 1) == 1) --read the cmd byte
	if cbuf.cmd == 0 then --data
		assert(read_file(p, 2) == 2)
		local len = bswap16(cbuf.len)
		assert(read_file(dbuf, len) == len)
		write_cmd('data', dbuf, len)
	elseif cbuf.cmd == 1 then --copy
		assert(read_file(p, 2+8) == 2+8)
		local len = bswap16(cbuf.len)
		local ofs = bswap64(cbuf.offset)
		write_cmd('copy', ofs, len)
	else
		error'invalid command'
	end
end

local function patch(read_cmd, read_file, write_file)
	for cmd, arg1, arg2 in read_cmd do
		if cmd == 'copy' then
			local ofs, len = arg1, arg2
			--read_file(
			copy(arg1, arg2) --offset, len
		elseif cmd == 'data' then
			local data, len = arg1, arg2
			write(arg1, arg2) --data, len
		end
	end
end

return {
	--algorithm
	rollsum = rollsum,
	gen_signatures = gen_signatures,
	gen_delta = gen_delta,
	--serialization
	sig_serializer = sig_serializer,
	sig_loader = sig_loader,
	delta_serializer = delta_serializer,
	patch = patch,
}
