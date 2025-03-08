local t1 = { unpack({ 1, 2, 3, nil, 5 }) }
assert(t1[5] == 5)


t1 = { unpack({ 1, 2, 3, nil, 5, nil }) }
assert(t1[5] == nil)
assert(t1[3] == 3)


local t1 = { unpack({ 1, 2, 3, nil, 5, nil, nil }) }
assert(t1[5] == 5)

t1 = { unpack({ 1, 2, 3, nil, 5, nil, nil, 8 }) }
assert(t1[8] == 8)
assert(t1[3] == 3)

t1 = { unpack({ 1, 2, 3, nil, 5, nil, nil, 8, nil }) }
assert(t1[8] == nil)
assert(t1[3] == 3)


function foo(...)
	return {...}
end

t1 = { unpack({ 1, 2, 3, nil, 5 }) }
assert(t1[5] == 5)
assert(select(5, unpack(t1))  == 5)

t1 = foo(1, 2, 3, nil, 5)
assert(t1[5] == 5)
assert(select(5, unpack(t1))  == 5)
