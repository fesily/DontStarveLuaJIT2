function test(str, target)
    local fmt = "return '%s'"
    local fn, err = loadstring(fmt:format(str))
    assert(fn, err)
    assert(fn() == target, fn())
end

test([[\%]], "%")
test([[\98]], "b")
