--go@ x:/luapower/bin/mingw64/luajit "rsync.lua"

--rsync algorithm in Lua.
--Written by Cosmin Apreutesei. Public Domain.

local ffi = require'ffi'
local bit = require'bit'
local ringbuffer = require'ringbuffer'
local shl, bor, band = bit.lshift, bit.bor, bit.band

local DEFAULT_BLOCK_LEN = 1024
local R = 31

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

--transforms `read() -> buf, len` into `read() -> buf, len1, end_of_block`
--where len1 <= block_len.
local function block_reader(read, block_len)
	local w = block_len
	local buf, o, r = nil, 0, 0
	return function()
		while r == 0 do
			buf, r = read()
			if not buf then return end
			r = r or #buf
			assert(r >= 0)
			o = 0
		end
		if w == 0 then
			w = block_len
		end
		local n = math.min(w, r)
		local end_of_block = n == w
		local o0 = o
		o = o + n
		w = w - n
		r = r - n
		return buf + o0, n, end_of_block
	end
end

--generate weak and strong signatures for all the blocks of a stream
local function gen_signatures(read, write, digest, block_len)
	local block_len = block_len or DEFAULT_BLOCK_LEN
	local d1 = rollsum()
	local d2 = digest()
	for buf, len, eob in block_reader(read, block_len) do
		d1:update(buf, len)
		d2:update(buf, len)
		if eob then
			write(d1:final(), d2:final())
			d1:reset()
			d2:reset()
		end
	end
	write(d1:final(), d2:final())
end

--generate deltas for a stream and a list of strong+weak signature pairs
local function gen_delta(read, read_sigs, write, digest, block_len)
	local block_len = block_len or DEFAULT_BLOCK_LEN

	local t = {} --{sig1 -> sig2}
	local offset = 0
	for sig1, sig2 in read_sigs do
		--print(bit.tohex(sig1), require'glue'.tohex(sig2))
		t[sig1] = {offset, sig2}
		offset = offset + block_len
	end

	local rb = ringbuffer{size = block_len, ctype = 'uint8_t'}
	local d1 = rollsum()
	local d2 = digest()

	local hashed, byte1
	local offset = 0
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
		local v = t[sig1]
		if v then
			local offset1, sig2 = v[1], v[2]
			d2:reset()
			local i1, n1, i2, n2 = rb:segments()
			d2:update(rb.data + i1, n1)
			if n2 > 0 then
				d2:update(rb.data + i2, n2)
			end
			if sig2 == d2:final() then
				write('copy', offset1, rb.length)
				offset = offset + rb.length
				rb:pull(rb.length)
				byte1 = nil
				hashed = nil
				return
			end
		end
		if byte1 then
			write('data', string.char(byte1), bit.tohex(sig1))
		end
		local i = rb:pull(1)
		byte1 = rb.data[i]
	end

	for buf, len in read do
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
	if rb.length > 0 then
		check_rb()
	end
end


if not ... then

	local blake2 = require'blake2'
	local stdio = require'stdio'
	local digest = blake2.blake2s_digest

	local block_len = 2
	local f = io.open't1.txt'
	local t = {}
	local sz = 1024
	local buf = ffi.new('uint8_t[?]', sz)
	gen_signatures(
		function()
			local n = assert(stdio.read(f, buf, sz))
			if n == 0 then return end
			return buf, n
		end,
		function(sig1, sig2)
			table.insert(t, sig1)
			table.insert(t, sig2)
			--print(bit.tohex(sig1), glue.tohex(sig2))
		end,
		digest,
		block_len)
	f:close()

	if true then

		local f = io.open't2.txt'
		local i = 1
		gen_delta(
			function()
				local n = assert(stdio.read(f, buf, sz))
				if n == 0 then return end
				return buf, n
			end,
			function()
				local sig1, sig2 = t[i], t[i+1]
				i = i + 2
				return sig1, sig2
			end,
			function(cmd, ...)
				print(cmd, ...)
			end,
			digest,
			block_len)
		f:close()

	end

	if false then

		local time = require'time'

		local len = 1024^2*10 --100 MB
		local buf = ffi.new('uint8_t[?]', len)
		print'writing'
		for i=0,len-1 do
			buf[i] = math.random(256) - 1
		end

		local i1 = 2000005
		local n  = 3000001
		local d  = 1234565

		rs1 = rollsum()
		rs1:update(buf + i1, n)
		local h1 = rs1:final()

		rs2 = rollsum()
		rs2:update(buf + i1 - d, n)
		for i=0,d-1 do
			rs2:rotate(buf[i1 - d + i], buf[i1 - d + i + n])
		end
		local h2 = rs2:final()

		assert(h1 == h2)
		print(h1, h2)

		math.randomseed(time.clock())

		print'summing'
		local t0 = time.clock()
		local rs = rollsum()
		local left = len
		local i = 0
		local n = 0
		while left > 0 do
			local sz = math.random(left)
			rs:update(buf + i, sz)
			left = left - sz
			i = i + sz
			n = n + 1
		end
		local d1 = rs:final()
		local t1 = time.clock()
		print(n, d1, len / 1024^2 / (t1 - t0))

		require'jit'.flush()
		local t0 = time.clock()
		local rs = rollsum()
		rs:update(buf, len)
		local d2 = rs:final()
		local t1 = time.clock()
		print(1, d2, len / 1024^2 / (t1 - t0))

		assert(d1 == d2)

	end

end
