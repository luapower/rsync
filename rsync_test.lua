local glue = require'glue'
local ffi = require'ffi'
local rsync = require'rsync'
local blake2 = require'blake2'
local stdio = require'stdio'
local pp = require'pp'

local weak_sum = rsync.rollsum
local strong_sum = blake2.blake2s_digest

local function string_reader(s)
	return function(buf, sz)
		sz = math.min(sz, #s)
		ffi.copy(buf, s, sz)
		s = s:sub(sz + 1)
		return sz
	end
end

local function test(s1, s2, block_len, expected)
	print(pp.format(s1), pp.format(s2), block_len)

	local read_file = string_reader(s1)

	local sigs = {}
	local function write_sigs(weak_sig, strong_sig)
		sigs[#sigs+1] = weak_sig
		sigs[#sigs+1] = strong_sig
	end

	rsync.gen_signatures(read_file, write_sigs,
		weak_sum, strong_sum, block_len)

	local read_file = string_reader(s2)

	local i = -1
	local function read_sig()
		i = i + 2
		return sigs[i], sigs[i+1]
	end

	local actual = {}
	local function write_cmd(cmd, ...)
		actual[#actual+1] = cmd
		if cmd == 'copy' then
			local block_num = ...
			--print('', cmd, block_num)
			actual[#actual+1] = block_num
		elseif cmd == 'data' then
			local buf, len = ...
			local s = ffi.string(buf, len)
			--print('', cmd, pp.format(s))
			actual[#actual+1] = s
		else
			assert(false)
		end
	end
	rsync.gen_deltas(read_file, read_sig, write_cmd,
		weak_sum, strong_sum, block_len)

	local ok = #expected == #actual
	for i = 1, math.max(#expected, #actual) do
		if ok then
			ok = expected[i] == actual[i]
		end
	end
	if not ok then
		for i = 1, math.max(#expected, #actual) do
			print('', expected[i], actual[i])
		end
	end

	local i = -1
	local function read_cmd()
		i = i + 2
		return actual[i], actual[i+1]
	end

	local function read_data(offset, buf, len)
		assert(#s1 >= offset + len)
		ffi.copy(buf, ffi.cast('char*', s1) + offset, len)
	end

	local t = {}
	local function write_data(buf, len)
		t[#t+1] = ffi.string(buf, len)
	end

	rsync.patch(read_cmd, read_data, write_data, block_len)

	local s3 = table.concat(t)
	assert(s3 == s2)

end

--trivial cases
test('', 'x', 1, {'data', 'x'})
test('x', '', 1, {})
test('x', 'x', 1, {'copy', 1})
test('a', 'b', 1, {'data', 'b'})
test('xa', 'xb', 1, {'copy', 1, 'data', 'b'})
test('ax', 'bx', 1, {'data', 'b', 'copy', 2})
test('ab', 'abab', 2, {'copy', 1, 'copy', 1})
test('abc', 'cba', 1, {'copy', 3, 'copy', 2, 'copy', 1})
test('aa', 'xaa', 2, {'data', 'x', 'copy', 1})
test('aa', 'xaab', 2, {'data', 'x', 'copy', 1, 'data', 'b'})
test('aa', 'xaabb', 2, {'data', 'x', 'copy', 1, 'data', 'b', 'data', 'b'})
test('aabb', 'xaabb', 2, {'data', 'x', 'copy', 1, 'copy', 2})
test('aabb', 'xaabby', 2, {'data', 'x', 'copy', 1, 'copy', 2, 'data', 'y'})

--files

