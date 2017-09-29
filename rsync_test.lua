local ffi = require'ffi'
local rsync = require'rsync'
local blake2 = require'blake2'
local stdio = require'stdio'
local weak_sum = rsync.rollsum
local strong_sum = blake2.blake2s_digest

local block_len = 1024
local f = io.open'gl_funcs21.lua'--'t1.txt'
local t = {}
rsync.gen_signatures(
	function(buf, sz)
		return stdio.read(f, buf, sz)
	end,
	function(sig1, sig2)
		table.insert(t, sig1)
		table.insert(t, sig2)
		--print(bit.tohex(sig1), glue.tohex(sig2))
	end,
	weak_sum,
	strong_sum,
	block_len)
f:close()

if true then

	local f = io.open'gl_funcs21-2.lua'--'t2.txt'
	local i = 1
	rsync.gen_delta(
		function(buf, sz)
			return stdio.read(f, buf, sz)
		end,
		function()
			local sig1, sig2 = t[i], t[i+1]
			i = i + 2
			return sig1, sig2
		end,
		function(cmd, ...)
			print(cmd, ...)
		end,
		weak_sum,
		strong_sum,
		block_len,
		block_len * 64 - 1)
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
