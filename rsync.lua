--go@ x:/luapower/bin/mingw64/luajit "rsync.lua"

--rsync algorithm in Lua.
--Written by Cosmin Apreutesei. Public Domain.

if not ... then require'rsync_test' end

local ffi = require'ffi'
local bit = require'bit'
local ringbuffer = require'ringbuffer'
local shl, shr, bor, band = bit.lshift, bit.rshift, bit.bor, bit.band
local pp = require'pp'

local default_block_len = 1024

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
local function gen_signatures(
	read_data,
	write_sigs,
	weak_sum,
	strong_sum,
	block_len
)
	local block_len = block_len or default_block_len
	local weak_sum = weak_sum()
	local strong_sum = strong_sum()
	local buf = ffi.new('uint8_t[?]', block_len)
	while true do
		local len = assert(read_data(buf, block_len))
		if len ~= block_len then break end
		weak_sum:reset()
		strong_sum:reset()
		weak_sum:update(buf, len)
		strong_sum:update(buf, len)
		write_sigs(weak_sum:final(), strong_sum:final())
	end
end

--generate deltas for a stream and a list of strong+weak signature pairs
local function gen_deltas(
	read_data,
	read_sigs,
	write_cmd,
	weak_sum,
	strong_sum,
	block_len,
	buf_size
)

	local block_len = block_len or default_block_len

	local weak_sigs = {}
	local strong_sigs = {}
	local block_num = 1
	for weak_sig, strong_sig in read_sigs do
		weak_sigs[weak_sig] = true
		strong_sigs[strong_sig] = block_num
		block_num = block_num + 1
	end

	local mem_len = math.max(block_len * 2, buf_size or 0)
	local mem = ffi.new('uint8_t[?]', mem_len)
	local data = mem
	local block = mem
	local data_len = read_data(data, mem_len)

	if data_len < block_len then
		if data_len > 0 then
			write_cmd('data', data, data_len)
		end
		return
	end

	local weak_sum = weak_sum()
	local strong_sum = strong_sum()

	--take a function which operates on a buffer segment and which has the
	--same effect if called multiple times on consecutive pieces of that
	--segment and turn it into a function that works on a ringbuffer.
	local function split(f)
		return function(p, len)
			if len == 0 then
				return 0
			end
			if p + len > mem + mem_len then
				local len1 = mem_len - (p - mem)
				local r1 = f(p, len1)
				local r2 = f(p, len - len1)
				return r1, r2
			else
				return f(p, len), 0
			end
		end
	end

	local update_weak_sum = split(function(p, len)
		weak_sum:update(p, len)
	end)
	local update_strong_sum = split(function(p, len)
		strong_sum:update(p, len)
	end)
	local write_data = split(function(p, len)
		write_cmd('data', p, len)
	end)
	local load_data = split(function(p, len)
		return read_data(p, len)
	end)

	local function ptr_inc(p, len)
		if (p - mem) + len >= mem_len then
			return p + len - mem_len
		else
			return p + len
		end
	end

	local function ptr_diff(p1, p2)
		local diff = p1 - p2
		if diff < 0 then
			return diff + mem_len
		else
			return diff
		end
	end

	local function load_more_data(required_len)
		local free_len = mem_len - data_len
		assert(free_len >= required_len)
		while required_len > 0 do
			local len1, len2 = load_data(ptr_inc(data, data_len), free_len)
			local len = len1 + len2
			if len == 0 then return end --eof
			data_len = data_len + len
			free_len = free_len - len
			required_len = required_len - len
		end
		return true
	end

	local function write_data_before_block()
		local write_len = ptr_diff(block, data)
		if write_len == 0 then return end
		write_data(data, write_len)
		data = block
		data_len = data_len - write_len
	end

	::check_new_block::
	weak_sum:reset()
	strong_sum:reset()
	update_weak_sum(block, block_len)

	::check_block::
	do
		local weak_sig = weak_sum:final()
		if not weak_sigs[weak_sig] then
			goto advance_block
		end
		update_strong_sum(block, block_len)
		local strong_sig = strong_sum:final()
		local block_num = strong_sigs[strong_sig]
		if not block_num then
			goto advance_block
		end

		write_data_before_block()

		write_cmd('copy', block_num)
		block = ptr_inc(block, block_len)
		data = block
		data_len = data_len - block_len

		if data_len < block_len then
			if not load_more_data(block_len - data_len) then
				goto finish
			end
		end
		goto check_new_block
	end

	::advance_block::
	do
		local lost_byte = block[0]
		block = ptr_inc(block, 1)
		if ptr_diff(block, data) + block_len > data_len then
			write_data_before_block()
			if not load_more_data(1) then
				goto finish
			end
		end
		weak_sum:rotate(lost_byte, ptr_inc(block, block_len-1)[0])
		goto check_block
	end

	::finish::
	if data_len > 0 then
		write_data(data, data_len)
	end

end

local function patch(read_cmd, read_data, write_data, block_len)
	block_len = block_len or default_block_len
	local block = ffi.new('uint8_t[?]', block_len)
	for cmd, arg1, arg2 in read_cmd do
		if cmd == 'copy' then
			local offset = (arg1 - 1) * block_len --arg1 is block_num
			read_data(offset, block, block_len)
			write_data(block, block_len)
		elseif cmd == 'data' then
			write_data(arg1, arg2 or #arg1) --(buf, sz) or (string)
		end
	end
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

local function sig_serializer(write_file, strong_sig_len)
	local ibuf = ffi.new'int32_t[1]'
	return function(weak_sig, strong_sig)
		ibuf[0] = bswap(weak_sig)
		write_file(ffi.cast('const char*', ibuf), 4)
		write_file(ffi.cast('const char*', strong_sig), strong_sig_len)
	end
end

local function sig_loader(read_data, strong_sig_len)
	local ibuf = ffi.new'int32_t[1]'
	local sbuf = ffi.new('uint8_t[?]', strong_sig_len)
	return function()
		assert(read_data(ibuf, 4) == 4)
		local weak_sig = bswap(ibuf[0])
		assert(read_data(sbuf, strong_sig_len) == strong_sig_len)
		local strong_sig = ffi.string(sbuf, strong_sig_len)
		return weak_sig, strong_sig
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

local function delta_loader(read_data, write_cmd)
	local cbuf = delta_ct()
	local p = ffi.cast('char*', cbuf)+1
	local dbuf = ffi.new('uint8_t[?]', 2^16)
	assert(read_data(p, 2+8) == 2+8)
	assert(read_data(cbuf, 1) == 1) --read the cmd byte
	if cbuf.cmd == 0 then --data
		assert(read_data(p, 2) == 2)
		local len = bswap16(cbuf.len)
		assert(read_data(dbuf, len) == len)
		write_cmd('data', dbuf, len)
	elseif cbuf.cmd == 1 then --copy
		assert(read_data(p, 2+8) == 2+8)
		local len = bswap16(cbuf.len)
		local ofs = bswap64(cbuf.offset)
		write_cmd('copy', ofs, len)
	else
		error'invalid command'
	end
end

return {
	--algorithm
	rollsum = rollsum,
	gen_signatures = gen_signatures,
	gen_deltas = gen_deltas,
	--serialization
	sig_serializer = sig_serializer,
	sig_loader = sig_loader,
	delta_serializer = delta_serializer,
	patch = patch,
}
