return function (path)
    path = MODROOT.."bin64/"..path .."/"

    ---@return file*
    local function create_handler(path, fn)
        local old_input = fn()
        fn(path)
        local input = fn()
        fn(old_input)
        return input
    end

    return function (filename)
        local input = create_handler(path..filename, io.input)
        local output = create_handler("../bin64/"..filename, io.output)
        local allInputs = input:read("*a")
        output:write(allInputs)
        input:close()
        output:close()
    end
end