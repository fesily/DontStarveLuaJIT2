local function test(...)
    local arg = {...}
    arg[1] = 2
    assert(arg[1] == 2)
    if 1 then
        assert(arg[1] == 2)
    end
    local limit = true
    while limit do
        assert(arg[1] == 2)
        limit = false
    end
    do
        assert(arg[1] == 2)
    end
    repeat
        assert(arg[1] == 2)
    until true
end
local function test1(...)
    assert(arg[1] == 2)
    if 1 then
        assert(arg[1] == 2)
    end
    local limit = true
    while limit do
        assert(arg[1] == 2)
        limit = false
    end
    do
        assert(arg[1] == 2)
    end
    repeat
        assert(arg[1] == 2)
    until true
end
local function test3(a,b,...)
    assert(arg)
end
test(1)
test1(2)
test3()
test3(1,2,3)
