-- 请勿在本文件内修改任何一个字符或空格
O = {
    o = function() return { 'Encrypted by 风雪，祝您生活愉快~ frostxx@qq.com' } end,
    O = function()
        return
        [[~喵嗷喵嗷嗷嗷呜喵嗷呜呜呜喵~呜呜喵~~呜嗷嗷呜呜喵嗷嗷嗷呜~呜喵呜喵喵~~嗷喵嗷~~呜嗷嗷~喵呜喵~~嗷喵~喵喵喵喵嗷~喵呜~喵~~喵喵喵嗷~~呜~呜嗷嗷~呜喵嗷喵呜呜呜喵呜~喵~嗷嗷呜~呜喵呜喵喵喵~嗷~喵呜喵喵呜喵喵喵~喵嗷喵~呜嗷呜呜喵~嗷喵嗷嗷~嗷喵嗷喵喵~喵喵喵嗷喵呜呜嗷呜喵喵嗷呜~喵呜~喵嗷呜~~呜~喵~~呜~喵喵喵呜~喵呜嗷喵嗷喵喵~喵喵喵呜呜嗷嗷嗷嗷~~~呜~喵~~~嗷嗷嗷嗷喵嗷呜~喵喵嗷喵喵喵呜嗷喵~呜~~呜喵~~嗷呜嗷呜呜喵~~~~嗷嗷嗷~~喵喵嗷喵喵喵呜嗷喵呜嗷呜喵~喵呜~~嗷~喵嗷嗷~喵嗷嗷嗷喵喵喵喵喵嗷~喵嗷喵~嗷喵~呜喵呜呜喵喵呜嗷喵~~呜嗷~~喵嗷~~呜呜呜喵呜喵喵呜喵嗷喵~~嗷喵~~嗷喵喵嗷~呜嗷嗷嗷呜~喵嗷~~嗷呜嗷~呜嗷嗷~嗷喵嗷喵~~嗷呜呜喵呜~喵嗷呜嗷呜呜~嗷喵呜~喵喵呜呜呜嗷~喵嗷喵呜~~嗷嗷嗷喵喵嗷喵呜嗷呜~~~~嗷嗷喵呜嗷~呜~喵呜呜~呜嗷嗷喵喵~嗷嗷嗷喵~呜喵~嗷~嗷~喵呜嗷~嗷嗷嗷喵嗷呜~喵呜]]
    end
}
o = {
    O = function() return '0.00', '这是余额' end,
    o = function() return '0', '这是群友' end
}
O.o('尊嘟假嘟')
o.O('假嘟尊嘟')
O.O('尊嘟')
o.o('假嘟')
--GLOBAL.setmetatable(env, { __index = function(t, k) return GLOBAL.rawget(GLOBAL, k) end })
local tonumber = tonumber
local string_byte = string.byte
local string_char = string.char
local string_sub = string.sub
local string_gsub = string.gsub
local string_rep = string.rep
local table_concat = table.concat
local table_insert = table.insert
local math_ldexp = math.ldexp
local getfenv = getfenv or
    function()
        return _ENV
    end
local setmetatable = setmetatable
local pcall = pcall
local select = select
local _table_unpack = unpack or
    table.unpack
local tonumber = tonumber
local function main(serstr, myenv, ...)
    local v18 = 1
    local v19
    serstr = string_gsub(string_sub(serstr, 5), "..",
        function(v30)
            if (string_byte(v30, 2) == 79) then
                v19 = tonumber(string_sub(v30, 1, 1))
                return "";
            else
                local v81 = string_char(tonumber(v30, 16))
                if v19 then
                    local v91 = 0
                    local v92
                    while true do
                        if (v91 == 1) then
                            return v92
                        end
                        if (v91 == 0) then
                            v92 = string_rep(v81, v19)
                            v19 = nil
                            v91 = 1;
                        end
                    end
                else
                    return v81
                end
            end
        end)
    local function v20(v31, v32, v33)
        if v33 then
            local v82 = (v31 / ((5 - 3) ^ (v32 - (2 - 1)))) %
                (((3 - 0) - 1) ^ (((v33 - (2 - 1)) - (v32 - (620 - (555 + 64)))) + (932 - (857 + 74))))
            return v82 -
                (v82 % (569 - (367 + 201)));
        else
            local v83 = 927 - (214 + 713)
            local v84
            while true do
                if (v83 == ((1065 - (68 + 997)) + 0)) then
                    v84 = (1 + 1) ^ (v32 - (878 - (282 + (1865 - (226 + 1044)))))
                    return (((v31 % (v84 + v84)) >= v84) and ((7132 - 5494) - (1523 + 114))) or
                        (0 + 0);
                end
            end
        end
    end
    local function v21()
        local v34 = string_byte(serstr, v18, v18)
        v18 = v18 + 1
        return v34;
    end
    local function v22()
        local v35 = 117 - (32 + 85)
        local v36
        local v37
        while true do
            if (v35 == (1 + 0)) then
                return (v37 * (57 + 199)) + v36
            end
            if (v35 == (957 - ((1637 - 745) + (415 - (87 + 263))))) then
                v36, v37 = string_byte(serstr, v18, v18 + (4 - 2))
                v18 = v18 + (3 - 1)
                v35 = 1;
            end
        end
    end
    local function v23()
        local v38 = 0
        local v39
        local v40
        local v41
        local v42
        while true do
            if (v38 == (181 - (67 + 113))) then
                return (v42 * ((33121891 - 20819614) + 4474939)) +
                    (v41 * ((291868 - 130967) - 95365)) + (v40 * (189 + 67)) + v39
            end
            if (v38 == 0) then
                v39, v40, v41, v42 = string_byte(serstr, v18, v18 + 3)
                v18 = v18 + (15 - 11)
                v38 = 953 - (802 + 150);
            end
        end
    end
    local function v24()
        local v43 = v23()
        local v44 = v23()
        local v45 = 1 + 0
        local v46 = (v20(v44, 1, 1017 - (915 + 82)) * (((1491 - (998 + 488)) - 3) ^ (19 + 13))) +
            v43
        local v47 = v20(v44, 21, (13 + 27) - 9)
        local v48 = ((v20(v44, 1219 - (1069 + 118)) == (2 - (1 + 0))) and -(1 - 0)) or
            (1 + 0)
        if (v47 == (0 - 0)) then
            if (v46 == (0 + (772 - (201 + 571)))) then
                return v48 * (791 - (368 + 423))
            else
                local v93 = 0 - 0
                while true do
                    if (v93 == (18 - (10 + (1146 - (116 + 1022))))) then
                        v47 = 1
                        v45 = (0 - 0) - (0 + 0)
                        break;
                    end
                end
            end
        elseif (v47 == (2489 - (416 + 26))) then
            return ((v46 == 0) and (v48 * ((3 - 2) / (0 + 0)))) or
                (v48 * NaN)
        end
        return math_ldexp(v48, v47 - (1809 - 786)) * (v45 + (v46 / ((440 - (145 + 293)) ^ (482 - (44 + 386)))));
    end
    local function v25(v49)
        local v50 = 0 - 0
        local v51
        local v52
        while true do
            if (v50 == 3) then
                return table_concat(v52)
            end
            if (v50 == (3 - (6 - 4))) then
                v51 = string_sub(serstr, v18, (v18 + v49) - (860 - (814 + 45)))
                v18 = v18 + v49
                v50 = 2;
            end
            if ((0 - 0) == v50) then
                v51 = nil
                if not v49 then
                    local v102 = 0 + 0
                    while true do
                        if ((0 + (0 - 0)) == v102) then
                            v49 = v23()
                            if (v49 == (885 - (103 + 158 + 624))) then
                                return ""
                            end
                            break;
                        end
                    end
                end
                v50 = 1 - 0;
            end
            if (2 == v50) then
                v52 = {}
                for v94 = 1081 - (1020 + 60), #v51 do
                    v52[v94] = string_char(string_byte(string_sub(v51, v94, v94)))
                end
                v50 = 1426 - (630 + 793);
            end
        end
    end
    local v26 = v23
    local function table_pack(...)
        return { ... }, select("#", ...)
    end
    local function decode_serstr()
        local v53 = 0 + 0
        local v54
        local v55
        local v56
        local v57
        local v58
        local v59
        local v60
        while true do
            if (1 == v53) then
                local v88 = 0 - 0
                local v89
                while true do
                    if (v88 == (1467 - (899 + 568))) then
                        v89 = 0
                        while true do
                            if (v89 == (1 + 0)) then
                                v53 = 4 - 2
                                break;
                            end
                            if (v89 == (603 - (268 + 335))) then
                                local v103 = 0
                                while true do
                                    if (v103 ~= 0) then else
                                        v56 = nil
                                        v57 = nil
                                        v103 = 291 - (60 + 230);
                                    end
                                    if (v103 == (573 - (426 + 146))) then
                                        v89 = 1
                                        break;
                                    end
                                end
                            end
                        end
                        break;
                    end
                end
            end
            if (v53 == (1 + 1)) then
                v58 = nil
                v59 = nil
                v53 = 1459 - (282 + 1174);
            end
            if (v53 ~= (811 - (569 + 242))) then else
                local v90 = 0
                while true do
                    if (v90 ~= (0 - 0)) then else
                        v54 = 0 + 0
                        v55 = nil
                        v90 = 1;
                    end
                    if (v90 == (1025 - (706 + 318))) then
                        v53 = 1252 - (721 + 530)
                        break;
                    end
                end
            end
            if (v53 == 3) then
                v60 = nil
                while true do
                    local v96 = 1271 - (945 + 326)
                    local v97
                    while true do
                        if (v96 == 0) then
                            v97 = 0 - 0
                            while true do
                                if (v97 == 1) then
                                    if (3 == v54) then
                                        local v105 = 0
                                        local v106
                                        local v107
                                        while true do
                                            if (v105 == 1) then
                                                while true do
                                                    if (v106 == (0 + 0)) then
                                                        v107 = 0
                                                        while true do
                                                            if ((700 - (271 + 429)) ~= v107) then else
                                                                for v434 = 1, v23() do
                                                                    v56[v434 - (1 + 0)] = decode_serstr()
                                                                end
                                                                return v58;
                                                            end
                                                        end
                                                        break;
                                                    end
                                                end
                                                break;
                                            end
                                            if (v105 == (1500 - (1408 + 92))) then
                                                v106 = 0
                                                v107 = nil
                                                v105 = 1087 - (461 + 625);
                                            end
                                        end
                                    end
                                    if (v54 ~= 1) then else
                                        local v108 = 0
                                        local v109
                                        local v110
                                        while true do
                                            if (v108 == 0) then
                                                v109 = 1288 - (993 + 295)
                                                v110 = nil
                                                v108 = 1 + 0;
                                            end
                                            if (v108 ~= (1172 - (418 + 753))) then else
                                                while true do
                                                    if (v109 == (0 + 0)) then
                                                        v110 = 0 + 0
                                                        while true do
                                                            if (v110 ~= (0 + 0)) then else
                                                                local v423 = 0
                                                                while true do
                                                                    if (v423 == 1) then
                                                                        v110 = 1 + 0
                                                                        break;
                                                                    end
                                                                    if (0 == v423) then
                                                                        local v440 = 0
                                                                        while true do
                                                                            if (v440 == (530 - (406 + 123))) then
                                                                                v423 = 1770 - (1749 + 20)
                                                                                break;
                                                                            end
                                                                            if (v440 == 0) then
                                                                                v58 = { v55, v56, nil, v57 }
                                                                                v59 = v23()
                                                                                v440 = 1 +
                                                                                    0;
                                                                            end
                                                                        end
                                                                    end
                                                                end
                                                            end
                                                            if (v110 ~= 1) then else
                                                                v60 = {}
                                                                v54 = 2
                                                                break;
                                                            end
                                                        end
                                                        break;
                                                    end
                                                end
                                                break;
                                            end
                                        end
                                    end
                                    break;
                                end
                                if (v97 == (1322 - (1249 + 73))) then
                                    local v104 = 0
                                    while true do
                                        if (v104 == 1) then
                                            v97 = 1
                                            break;
                                        end
                                        if (v104 == 0) then
                                            if (v54 == 2) then
                                                local v148 = 0 + 0
                                                local v149
                                                local v150
                                                while true do
                                                    if (1 == v148) then
                                                        while true do
                                                            if (v149 ~= 0) then else
                                                                v150 = 0
                                                                while true do
                                                                    if (v150 == 1) then
                                                                        for v442 = 1146 - (466 + 679), v23() do
                                                                            local v443 = 0
                                                                            local v444
                                                                            local v445
                                                                            local v446
                                                                            while true do
                                                                                if (v443 == 1) then
                                                                                    v446 = nil
                                                                                    while true do
                                                                                        if (v444 ~= 1) then else
                                                                                            while true do
                                                                                                if (v445 ~= (0 - 0)) then else
                                                                                                    v446 = v21()
                                                                                                    if (v20(v446, 2 - 1, 1901 - (106 + 1794)) == 0) then
                                                                                                        local v459 = 0
                                                                                                        local v460
                                                                                                        local v461
                                                                                                        local v462
                                                                                                        local v463
                                                                                                        local v464
                                                                                                        while true do
                                                                                                            if (v459 == 1) then
                                                                                                                v462 = nil
                                                                                                                v463 = nil
                                                                                                                v459 = 2;
                                                                                                            end
                                                                                                            if ((0 + 0) == v459) then
                                                                                                                v460 = 0 +
                                                                                                                    0
                                                                                                                v461 = nil
                                                                                                                v459 = 1;
                                                                                                            end
                                                                                                            if (v459 ~= 2) then else
                                                                                                                v464 = nil
                                                                                                                while true do
                                                                                                                    if (v460 == 2) then
                                                                                                                        while true do
                                                                                                                            if (v461 == (0 - 0)) then
                                                                                                                                v462 =
                                                                                                                                    v20(
                                                                                                                                        v446,
                                                                                                                                        2,
                                                                                                                                        3)
                                                                                                                                v463 =
                                                                                                                                    v20(
                                                                                                                                        v446,
                                                                                                                                        10 -
                                                                                                                                        6,
                                                                                                                                        6)
                                                                                                                                v461 = 1;
                                                                                                                            end
                                                                                                                            if ((116 - (4 + 110)) == v461) then
                                                                                                                                local v467 = 584 -
                                                                                                                                    (57 + 527)
                                                                                                                                while true do
                                                                                                                                    if (v467 ~= (1428 - (41 + 1386))) then else
                                                                                                                                        v461 = 3
                                                                                                                                        break;
                                                                                                                                    end
                                                                                                                                    if (v467 ~= (103 - (17 + 86))) then else
                                                                                                                                        if (v20(v463, 1 + 0, 1) ~= 1) then else
                                                                                                                                            v464[2] =
                                                                                                                                                v60[v464[2]]
                                                                                                                                        end
                                                                                                                                        if (v20(v463, 2, 2) ~= (1 - 0)) then else
                                                                                                                                            v464[8 - 5] =
                                                                                                                                                v60[v464[169 - (122 + 44)]]
                                                                                                                                        end
                                                                                                                                        v467 = 1 -
                                                                                                                                            0;
                                                                                                                                    end
                                                                                                                                end
                                                                                                                            end
                                                                                                                            if (v461 ~= (9 - 6)) then else
                                                                                                                                if (v20(v463, 3, 3) == 1) then
                                                                                                                                    v464[4 + 0] =
                                                                                                                                        v60[v464[1 + 3]]
                                                                                                                                end
                                                                                                                                v55[v442] =
                                                                                                                                    v464
                                                                                                                                break;
                                                                                                                            end
                                                                                                                            if ((1 - 0) == v461) then
                                                                                                                                local v469 = 0
                                                                                                                                while true do
                                                                                                                                    if (v469 ~= (66 - (30 + 35))) then else
                                                                                                                                        v461 = 2 +
                                                                                                                                            0
                                                                                                                                        break;
                                                                                                                                    end
                                                                                                                                    if (v469 == (1257 - (1043 + 214))) then
                                                                                                                                        v464 = {
                                                                                                                                            v22(),
                                                                                                                                            v22(), nil, nil }
                                                                                                                                        if (v462 == 0) then
                                                                                                                                            local v476 = 0
                                                                                                                                            local v477
                                                                                                                                            local v478
                                                                                                                                            while true do
                                                                                                                                                if (v476 == (1212 - (323 + 889))) then
                                                                                                                                                    v477 = 0
                                                                                                                                                    v478 = nil
                                                                                                                                                    v476 = 2 -
                                                                                                                                                        1;
                                                                                                                                                end
                                                                                                                                                if (v476 == (581 - (361 + 219))) then
                                                                                                                                                    while true do
                                                                                                                                                        if ((320 - (53 + 267)) ~= v477) then else
                                                                                                                                                            v478 = 0 +
                                                                                                                                                                0
                                                                                                                                                            while true do
                                                                                                                                                                if (v478 == 0) then
                                                                                                                                                                    v464[3] =
                                                                                                                                                                        v22()
                                                                                                                                                                    v464[4] =
                                                                                                                                                                        v22()
                                                                                                                                                                    break;
                                                                                                                                                                end
                                                                                                                                                            end
                                                                                                                                                            break;
                                                                                                                                                        end
                                                                                                                                                    end
                                                                                                                                                    break;
                                                                                                                                                end
                                                                                                                                            end
                                                                                                                                        elseif (v462 == 1) then
                                                                                                                                            v464[416 - (15 + 398)] =
                                                                                                                                                v23()
                                                                                                                                        elseif (v462 == 2) then
                                                                                                                                            v464[985 - (18 + 964)] =
                                                                                                                                                v23() -
                                                                                                                                                ((7 - 5) ^ (10 + 6))
                                                                                                                                        elseif (v462 == (2 + 1)) then
                                                                                                                                            local v481 = 850 -
                                                                                                                                                (20 + 830)
                                                                                                                                            local v482
                                                                                                                                            local v483
                                                                                                                                            local v484
                                                                                                                                            while true do
                                                                                                                                                if (v481 == 1) then
                                                                                                                                                    v484 = nil
                                                                                                                                                    while true do
                                                                                                                                                        if (1 ~= v482) then else
                                                                                                                                                            while true do
                                                                                                                                                                if (v483 == 0) then
                                                                                                                                                                    v484 = 0
                                                                                                                                                                    while true do
                                                                                                                                                                        if (v484 == (0 + 0)) then
                                                                                                                                                                            v464[3] =
                                                                                                                                                                                v23() -
                                                                                                                                                                                (2 ^ (142 - (116 + 10)))
                                                                                                                                                                            v464[1 + 3] =
                                                                                                                                                                                v22()
                                                                                                                                                                            break;
                                                                                                                                                                        end
                                                                                                                                                                    end
                                                                                                                                                                    break;
                                                                                                                                                                end
                                                                                                                                                            end
                                                                                                                                                            break;
                                                                                                                                                        end
                                                                                                                                                        if (v482 ~= 0) then else
                                                                                                                                                            v483 = 738 -
                                                                                                                                                                (542 + 196)
                                                                                                                                                            v484 = nil
                                                                                                                                                            v482 = 1;
                                                                                                                                                        end
                                                                                                                                                    end
                                                                                                                                                    break;
                                                                                                                                                end
                                                                                                                                                if (v481 == (0 - 0)) then
                                                                                                                                                    v482 = 0
                                                                                                                                                    v483 = nil
                                                                                                                                                    v481 = 1 +
                                                                                                                                                        0;
                                                                                                                                                end
                                                                                                                                            end
                                                                                                                                        end
                                                                                                                                        v469 = 1 +
                                                                                                                                            0;
                                                                                                                                    end
                                                                                                                                end
                                                                                                                            end
                                                                                                                        end
                                                                                                                        break;
                                                                                                                    end
                                                                                                                    if (v460 == 1) then
                                                                                                                        local v465 = 0 +
                                                                                                                            0
                                                                                                                        while true do
                                                                                                                            if (v465 == 1) then
                                                                                                                                v460 = 2
                                                                                                                                break;
                                                                                                                            end
                                                                                                                            if (0 ~= v465) then else
                                                                                                                                v463 = nil
                                                                                                                                v464 = nil
                                                                                                                                v465 = 2 -
                                                                                                                                    1;
                                                                                                                            end
                                                                                                                        end
                                                                                                                    end
                                                                                                                    if (v460 == 0) then
                                                                                                                        local v466 = 0
                                                                                                                        while true do
                                                                                                                            if (v466 == 1) then
                                                                                                                                v460 = 1
                                                                                                                                break;
                                                                                                                            end
                                                                                                                            if (v466 == 0) then
                                                                                                                                v461 = 0 -
                                                                                                                                    0
                                                                                                                                v462 = nil
                                                                                                                                v466 = 1552 -
                                                                                                                                    (1126 + 425);
                                                                                                                            end
                                                                                                                        end
                                                                                                                    end
                                                                                                                end
                                                                                                                break;
                                                                                                            end
                                                                                                        end
                                                                                                    end
                                                                                                    break;
                                                                                                end
                                                                                            end
                                                                                            break;
                                                                                        end
                                                                                        if (0 == v444) then
                                                                                            local v456 = 0
                                                                                            while true do
                                                                                                if ((405 - (118 + 287)) ~= v456) then else
                                                                                                    v445 = 0 - 0
                                                                                                    v446 = nil
                                                                                                    v456 = 1;
                                                                                                end
                                                                                                if (v456 ~= 1) then else
                                                                                                    v444 = 1122 -
                                                                                                        (118 + 1003)
                                                                                                    break;
                                                                                                end
                                                                                            end
                                                                                        end
                                                                                    end
                                                                                    break;
                                                                                end
                                                                                if (v443 == (0 - 0)) then
                                                                                    v444 = 377 - (142 + 235)
                                                                                    v445 = nil
                                                                                    v443 = 4 -
                                                                                        3;
                                                                                end
                                                                            end
                                                                        end
                                                                        v54 = 3
                                                                        break;
                                                                    end
                                                                    if (v150 ~= (0 + 0)) then else
                                                                        local v441 = 977 - (553 + 424)
                                                                        while true do
                                                                            if (v441 ~= (1 - 0)) then else
                                                                                v150 = 1 + 0
                                                                                break;
                                                                            end
                                                                            if (v441 == (0 + 0)) then
                                                                                for v451 = 1, v59 do
                                                                                    local v452 = 0 + 0
                                                                                    local v453
                                                                                    local v454
                                                                                    local v455
                                                                                    while true do
                                                                                        if (v452 == 1) then
                                                                                            v455 = nil
                                                                                            while true do
                                                                                                if ((0 + 0) == v453) then
                                                                                                    local v457 = 0 + 0
                                                                                                    while true do
                                                                                                        if (v457 == (0 - 0)) then
                                                                                                            v454 = v21()
                                                                                                            v455 = nil
                                                                                                            v457 = 2 -
                                                                                                                1;
                                                                                                        end
                                                                                                        if (v457 == (2 - 1)) then
                                                                                                            v453 = 1 + 0
                                                                                                            break;
                                                                                                        end
                                                                                                    end
                                                                                                end
                                                                                                if (v453 ~= 1) then else
                                                                                                    if (v454 == (4 - 3)) then
                                                                                                        v455 =
                                                                                                            v21() ~=
                                                                                                            (753 - (239 + 514))
                                                                                                    elseif (v454 == 2) then
                                                                                                        v455 =
                                                                                                            v24()
                                                                                                    elseif (v454 == 3) then
                                                                                                        v455 =
                                                                                                            v25()
                                                                                                    end
                                                                                                    v60[v451] = v455
                                                                                                    break;
                                                                                                end
                                                                                            end
                                                                                            break;
                                                                                        end
                                                                                        if (v452 == 0) then
                                                                                            v453 = 0 + 0
                                                                                            v454 = nil
                                                                                            v452 = 1330 -
                                                                                                (797 + 532);
                                                                                        end
                                                                                    end
                                                                                end
                                                                                v58[3] = v21()
                                                                                v441 = 1;
                                                                            end
                                                                        end
                                                                    end
                                                                end
                                                                break;
                                                            end
                                                        end
                                                        break;
                                                    end
                                                    if (v148 == 0) then
                                                        v149 = 0
                                                        v150 = nil
                                                        v148 = 1 + 0;
                                                    end
                                                end
                                            end
                                            if (v54 ~= (0 + 0)) then else
                                                local v151 = 0
                                                while true do
                                                    if (v151 == 0) then
                                                        v55 = {}
                                                        v56 = {}
                                                        v151 = 2 - 1;
                                                    end
                                                    if (1 ~= v151) then else
                                                        v57 = {}
                                                        v54 = 1
                                                        break;
                                                    end
                                                end
                                            end
                                            v104 = 1203 - (373 + 829);
                                        end
                                    end
                                end
                            end
                            break;
                        end
                    end
                end
                break;
            end
        end
    end
    local function v29(func, funcupvals, funcenv)
        local v64 = func[1]
        local v65 = func[2]
        local v66 = func[3]
        return function(...)
            local bcs = v64
            local subs = v65
            local num_param  = v66
            local table_pack = table_pack
            local pc = 1
            local top_index = -1
            local _unused = {}
            local args = { ... }
            local args_len =
                select("#", ...) - 1
            local open_list = {}
            local memory = {}
            for i = 0, args_len do
                if (i >= num_param ) then
                    _unused[i - num_param ] =
                        args[i + 1]
                else
                    memory[i] = args[i + 1]
                end
            end
            local _discard_args = (args_len - num_param ) + 1
            local bc
            local op
            while true do
                bc = bcs[pc]  -- 获取当前指令
                op = bc[1]    -- 获取操作码
            
                print("new ins", bc[1], bc[2], bc[3], bc[4])
                if op == 0 or op == 32 then
                    print("JMP", bc[3])
                    pc = bc[3]  -- 跳转到指定位置
                elseif op == 1 or op == 95 then
                    print("NEWTABLE", bc[2])
                    memory[bc[2]] = {}  -- 创建空表
                elseif op == 2 or op == 81 then
                    local v162 = bc[2]
                    print("CALL", v162, v162, v162 + 1)
                    memory[v162] = memory[v162](memory[v162 + 1])  -- 调用函数并存储结果
                elseif op == 3 or op == 96 then
                    print("CALL_NO_RESULT", nil, bc[2], bc[2], bc[3])
                    local v112 = bc[2]
                    memory[v112](_table_unpack(memory, v112 + 1, bc[3]))  -- 调用函数并传递参数
                elseif op == 10 or op == 18 then
                    print("TAILCALL", bc[2], bc[2]+1, top_index)
                    local v178 = bc[2]
                    return memory[v178](_table_unpack(memory, v178 + 1, top_index))  -- 调用函数并返回
                elseif op == 12 or op == 49 then
                    print("TAILCALL", bc[2], bc[2]+1, bc[3])
                    local v114 = bc[2]
                    return memory[v114](_table_unpack(memory, v114 + 1, bc[3]))  -- 调用函数并返回
                elseif op == 4 or op == 14 then
                    print("SETTABLE", bc[2], bc[3], bc[4])
                    local v164 = bc[2]
                    local v165 = memory[bc[3]]
                    memory[v164 + 1] = v165
                    memory[v164] = v165[bc[4]]  -- 表索引赋值
                elseif op == 5 or op == 50 then
                    print("MOVE", bc[2], bc[3])
                    memory[bc[2]] = memory[bc[3]]  -- 内存复制
                elseif op == 6 or op == 90 then
                    print("RETURN0")
                    return  -- 退出循环
                elseif op == 7 or op == 17 then
                    print("SETTABLE1", bc[2], bc[3], bc[4])
                    memory[bc[2]][bc[3]] = memory[bc[4]]  -- 表字段赋值
                elseif op == 9 or op == 70 then
                    print("LEN", bc[2], bc[3])
                    memory[bc[2]] = #memory[bc[3]]  -- 获取表长度
                elseif op == 11 or op == 58 then
                    print("GETGLOBAL", bc[2], bc[3])
                    if bc[3] == "_ENV" then
                        memory[bc[2]] = funcenv  -- 设置环境变量
                    else
                        memory[bc[2]] = funcenv[bc[3]]  -- 从环境中获取值
                    end

                elseif op == 13 or op == 68 then
                    local REG_A = bc[2]
                    local v183, v184 = table_pack(memory[REG_A](_table_unpack(memory, REG_A + 1, top_index)))
                    top_index = (v184 + REG_A) - 1
                    local v185 = 0
                    for v291 = REG_A, top_index do
                        v185 = v185 + 1
                        memory[v291] = v183[v185]  -- 解包赋值
                    end
                elseif op == 30 or op == 60 then
                    local REG_A = bc[2]
                    local v205, v206 = table_pack(memory[REG_A](_table_unpack(memory, REG_A + 1, bc[3])))
                    top_index = (v206 + REG_A) - 1
                    local v207 = 0
                    for v301 = REG_A, top_index do
                        v207 = v207 + 1
                        memory[v301] = v205[v207]  -- 解包赋值
                    end
                elseif op == 8 or op == 73 then
                    local REG_A = bc[2]
                    local v253, v254 = table_pack(memory[REG_A](memory[REG_A + 1]))
                    top_index = (v254 + REG_A) - 1
                    local v255 = 0
                    for v314 = REG_A, top_index do
                        v255 = v255 + 1
                        memory[v314] = v253[v255]  -- 解包赋值
                    end
                elseif op == 24 or op == 48 then
                    local REG_A = bc[2]
                    local v195 = { memory[REG_A](memory[REG_A + 1]) }  -- 调用函数并存储结果
                    local v196 = 0
                    for v293 = REG_A, bc[4] do
                        v196 = v196 + 1
                        memory[v293] = v195[v196]  -- 解包赋值
                    end
                elseif op == 29 or op == 75 then
                    local REG_A = bc[2]
                    local v200 = bc[4]
                    local v201 = REG_A + 2
                    local v202 = { memory[REG_A](memory[REG_A + 1], memory[v201]) }  -- 调用函数并存储结果
                    for v298 = 1, v200 do
                        memory[v201 + v298] = v202[v298]  -- 解包赋值
                    end
                    local v203 = v202[1]
                    if v203 then
                        memory[v201] = v203
                        pc = bc[3]  -- 条件跳转
                    else
                        pc = pc + 1
                    end
                elseif op == 67 or op == 91 then
                    local v245 = bc[2]
                    local v246 = { memory[v245](_table_unpack(memory, v245 + 1, bc[3])) }  -- 调用函数并存储结果
                    local v247 = 0
                    for v311 = v245, bc[4] do
                        v247 = v247 + 1
                        memory[v311] = v246[v247]  -- 解包赋值
                    end
                elseif op == 15 or op == 98 then
                    print("SETLIST", bc[2], bc[3])
                    local v115 = bc[2]
                    local v116 = memory[v115]
                    local v117 = bc[3]
                    for v152 = 1, v117 do
                        v116[v152] = memory[v115 + v152]  -- 表批量赋值
                    end
                elseif op == 16 or op == 97 then
                    print("TRUE")
                    if memory[bc[2]] then
                        pc = pc + 1
                    else
                        pc = bc[3]  -- 条件跳转
                    end
                elseif op == 19 or op == 69 then
                    memory[bc[2]] = memory[bc[3]][memory[bc[4]]]  -- 表索引取值
                elseif op == 20 or op == 21 then
                    print("LT")
                    if memory[bc[2]] < memory[bc[4]] then
                        pc = pc + 1
                    else
                        pc = bc[3]  -- 条件跳转
                    end
                elseif op == 36 or op == 87 then
                    print("LT")
                    if bc[2] < memory[bc[4]] then
                        pc = pc + 1
                    else
                        pc = bc[3]  -- 条件跳转
                    end
                elseif op == 22 or op == 56 then
                    memory[bc[2]] = funcupvals[bc[3]]  -- 从 v62 获取值
                elseif op == 23 or op == 25 then
                    print("GETTABLE", bc[2], bc[3], bc[4])
                    memory[bc[2]] = memory[bc[3]][bc[4]]  -- 表字段取值

                elseif op == 26 or op == 45 then
                    local v197 = bc[2]
                    memory[v197] = memory[v197]()  -- 调用函数并存储结果
                elseif op == 27 or op == 74 then
                    print("LE")
                    if memory[bc[2]] <= bc[4] then
                        pc = pc + 1
                    else
                        pc = bc[3]  -- 条件跳转
                    end
                elseif op == 28 or op == 101 then
                    print("NEWFUNC", bc[2], bc[3], bc[4])
                    local v122 = subs[bc[3]]
                    local real_upval = {}
                    local upvals = setmetatable({}, {
                        __index = function(t, k)
                            local val_pair = real_upval[k]
                            return val_pair[1][val_pair[2]]
                        end,
                        __newindex = function(t, k, v)
                            local v354 = real_upval[k]
                            v354[1][v354[2]] = v
                        end
                    })
                    for i = 1, bc[4] do
                        pc = pc + 1
                        local next_ins = bcs[pc]
                        local next_op = next_ins[1]
                        -- inline move
                        if next_op == 5 then --move
                            real_upval[i - 1] = { memory, next_ins[3] }
                        else
                            real_upval[i - 1] = { funcupvals, next_ins[3] }
                        end
                        open_list[#open_list + 1] = real_upval
                    end
                    memory[bc[2]] = v29(v122, upvals, funcenv)  -- 创建闭包


                elseif op == 31 or op == 92 then
                    local v125 = bc[2]
                    memory[v125](memory[v125 + 1])  -- 调用函数
                
                elseif op == 34 or  op == 83 then
                    print("EQ")
                    if memory[bc[2]] == bc[4] then
                        pc = pc + 1
                    else
                        pc = bc[3]  -- 条件跳转
                    end
                elseif op == 35 or op == 59 then
                    print("TEST")
                    local v211 = memory[bc[4]]
                    if not v211 then
                        pc = pc + 1
                    else
                        memory[bc[2]] = v211
                        pc = bc[3]  -- 条件跳转
                    end

                elseif op == 37 or op == 41 then
                    local v212 = bc[2]
                    memory[v212](_table_unpack(memory, v212 + 1, top_index))  -- 调用函数
                elseif op == 38 or op == 79 then
                    for v155 = bc[2], bc[3] do
                        memory[v155] = nil  -- 清空内存
                    end
                elseif op == 39 or op == 55 then
                    memory[bc[2]] = memory[bc[3]] - bc[4]  -- 减法赋值
                elseif op == 40 or op == 44 then
                    return memory[bc[2]]  -- 返回单个值
                elseif op == 42 or op == 52 then
                    print("EQ")
                    if bc[2] == memory[bc[4]] then
                        pc = pc + 1
                    else
                        pc = bc[3]  -- 条件跳转
                    end
                elseif op == 43 or op == 82 then
                    local v214 = bc[2]
                    memory[v214] = memory[v214](_table_unpack(memory, v214 + 1, top_index))  -- 调用函数并存储结果
                elseif op == 46 or op == 54 then
                    funcenv[bc[3]] = memory[bc[2]]  -- 设置环境变量
                elseif op == 47 or op == 89 then
                    print("NEWFUNC_47", bc[2], bc[3], bc[4])
                    memory[bc[2]] = v29(subs[bc[3]], nil, funcenv)  -- 创建闭包

              
                elseif op == 51 or op == 65 then
                    print("LOADK", bc[2], bc[3])
                    memory[bc[2]] = bc[3]  -- 赋值常量
             
                elseif op == 57 or op == 64 then
                    memory[bc[2]][memory[bc[3]]] = memory[bc[4]]  -- 表字段赋值
            
                elseif op == 61 or op == 88 then
                    print("CONCAT", bc[2], bc[3], bc[4])
                    local v233 = bc[3]
                    local v235 = memory[v233]
                    for v412 = v233 + 1, bc[4] do
                        v235 = v235 .. memory[v412]  -- 字符串拼接
                    end
                    memory[bc[2]] = v235
                elseif op == 62 or op == 63 then
                    if not memory[bc[2]] then
                        pc = pc + 1
                    else
                        pc = bc[3]  -- 条件跳转
                    end
                elseif op == 66 or op == 84 then
                    local v138 = bc[2]
                    memory[v138] = memory[v138](_table_unpack(memory, v138 + 1, bc[3]))  -- 调用函数并存储结果

                elseif op == 71 or op == 100 then
                    local REG_A = bc[2]
                    local Tab = memory[REG_A]
                    for v413 = REG_A + 1, top_index do
                        table_insert(Tab, memory[v413])  -- 表插入
                    end
                elseif op == 53 then
                    local REG_A = bc[2]
                    local Tab = memory[REG_A]
                    for v307 = REG_A + 1, bc[3] do
                        table_insert(Tab, memory[v307])  -- 表插入
                    end
                elseif op == 72 or op == 86 then
                    print("CALL_NO_RESULT_NO_PARAM", bc[2])
                    memory[bc[2]]()  -- 调用函数
                elseif op == 76 or op == 99 then
                    memory[bc[2]] = memory[bc[3]] + bc[4]  -- 加法赋值
                elseif op == 77 or op == 93 then
                    if memory[bc[2]] ~= memory[bc[4]] then
                        pc = pc + 1
                    else
                        pc = bc[3]  -- 条件跳转
                    end
                elseif op == 78 or op == 94 then
                    local v261 = bc[2]
                    return _table_unpack(memory, v261, top_index)  -- 返回解包值
                elseif op == 33 then
                    local v209 = bc[2]
                    return _table_unpack(memory, v209, v209 + bc[3])  -- 返回解包值
                elseif op == 80 or op == 85 then
                    local v263 = bc[2]
                    local v264 = {}
                    for v414 = 1, #open_list do
                        local v415 = open_list[v414]
                        for v426 = 0, #v415 do
                            local v427 = v415[v426]
                            local v428 = v427[1]
                            local v429 = v427[2]
                            if v428 == memory and v429 >= v263 then
                                v264[v429] = v428[v429]
                                v427[1] = v264
                            end
                        end
                    end

            
                end
            
                pc = pc + 1  -- 程序计数器自增
            end
        end;
    end
    local func = decode_serstr()
    local exits_ins_id = {}

    local function foreachbcs(func)
        for _, ins in ipairs(func[1]) do
            exits_ins_id[ins[1]] = true
        end
        for _, subf in ipairs(func[2]) do
            foreachbcs(subf)
        end
        local subf = func[2][0]
        if subf then
            foreachbcs(subf)
        end
    end
    foreachbcs(func)
    return v29(func, {}, myenv)(...);
end
main(
    "LOL!263O0003053O00646562756703073O00736574682O6F6B03073O00676574696E666F03063O00474C4F42414C03123O006465627567737461636B5F6F6E656C696E6503023O00696F03043O006F70656E03073O004D4F44522O4F54030B3O006D6F646D61696E2E6C7561026O004D40025O00C05640025O00389140026O004A40026O004640026O003440026O002C40028O0003053O006C696E6573026O00F03F026O00224003023O006F7303043O0074696D65026O00244003043O006461746103053O00636C6F736503023O005F4703073O0072657175697265030E3O004C6F616450726566616246696C6503093O006D6F64696D706F7274030C3O006D6F646D61696E302E6C7561030A3O006C6F6164737472696E6703013O005303063O00736F7572636503043O003D5B435D03043O007265616403023O002A6103073O0073657466656E762O033O00656E7600A23O00123A3O00013O0020195O00022O00483O0001000100123A3O00013O0020195O000300022F00015O00066500020001000100012O00053O00013O00123A000300043O00066500040002000100022O00053O00024O00057O00100700030005000400123A000300063O00201900030003000700123A000400083O001233000500094O00580004000400052O00020003000200022O005F000400093O0012330005000A3O0012330006000B3O0012330007000C3O0012330008000D3O0012330009000E3O001233000A000F3O001233000B000F3O001233000C00103O001233000D00104O0062000400090001001233000500113O0020040006000300122O003000060002000800044O00570001001233000A00113O002653000A003F0001001100044O003F000100204C00050005001300264A0005003E0001001400044O003E00012O0046000B00094O0045000C0004000500064D000B003E0001000C00044O003E0001001233000B00114O004F000C000C3O002653000B002E0001001100044O002E0001001233000C00113O002653000C00310001001100044O00310001001233000D00113O002653000D00340001001100044O0034000100123A000E00153O002019000E000E00162O0048000E000100012O005A3O00013O00044O0034000100044O0031000100044O003E000100044O002E0001001233000A00133O002653000A00230001001300044O00230001000E57001700570001000500044O00570001001233000B00114O004F000C000C3O002653000B00450001001100044O00450001001233000C00113O002653000C00480001001100044O00480001001233000D00113O002653000D004B0001001100044O004B000100123A000E00153O002019000E000E00182O0048000E000100012O005A3O00013O00044O004B000100044O0048000100044O0057000100044O0045000100044O0057000100044O0023000100061D000600220001000100044O002200010020040006000300192O005C00060002000100022F000600033O00123A0007001A3O00201900070007001B00066500080004000100022O00053O00064O00053O00073O0012360008001B3O00123A000800043O00123A0009001B3O0010070008001B000900123A0008001C3O00123A000900043O000665000A0005000100022O00053O00084O00053O00063O0010070009001C000A00123A0009001D3O000665000A0006000100022O00053O00064O00053O00093O001236000A001D3O00123A000A00063O002019000A000A000700123A000B00083O001233000C001E4O0058000B000B000C2O0002000A0002000200123A000B00013O002019000B000B000300123A000C001F3O001233000D00204O0054000B000D0002000661000B00A000013O00044O00A00001002019000C000B0021002653000C00A00001002200044O00A0000100123A000C001F4O0032000D00063O002004000E000A0023001233001000244O001E000E00104O000D000D6O002B000C3O0002002004000D000A00192O005C000D00020001000661000C009D00013O00044O009D0001001233000D00114O004F000E000E3O002653000D008D0001001100044O008D0001001233000E00113O002653000E00900001001100044O0090000100123A000F00254O00320010000C3O00123A001100264O0003000F001100012O0032000F000C4O0048000F0001000100044O00A0000100044O0090000100044O00A0000100044O008D000100044O00A000012O0032000D00093O001233000E001E4O005C000D000200012O00558O005A3O00013O00073O00063O00028O002O033O005B3F5D2O033O00737562026O00F03F03013O0040027O004001173O001233000100013O002653000100120001000100044O0012000100063E3O00070001000100044O00070001001233000200024O002C000200023O00200400023O0003001233000400043O001233000500044O0054000200050002002653000200110001000500044O0011000100200400023O0003001233000400064O00540002000400022O00323O00023O001233000100043O002653000100010001000400044O000100012O002C3O00023O00044O000100012O005A3O00017O00133O00028O00026O00F03F03063O00737472696E6703043O0066696E6403013O000A2O033O00737562027O004003093O002O2A652O726F722O2A03063O00736F75726365030B3O0063752O72656E746C696E6503013O003A031B3O0009257320696E20282573292025732028257329203C25642D25643E03063O00666F726D617403083O006E616D657768617403043O006E616D6503013O003F03043O0077686174030B3O006C696E65646566696E6564030F3O006C6173746C696E65646566696E656401383O001233000100014O004F000200043O002653000100150001000200044O0015000100123A000500033O0020190005000500042O0032000600023O001233000700054O005B0005000700062O0032000400064O0032000300053O0006610004001400013O00044O0014000100123A000500033O0020190005000500062O0032000600023O001233000700023O0020270008000400022O00540005000800022O0032000200053O001233000100073O002653000100200001000100044O0020000100063E3O001B0001000100044O001B0001001233000500084O002C000500024O001600055O00201900063O00092O00020005000200022O0032000200053O001233000100023O002653000100020001000700044O0002000100201900053O000A0006610005002900013O00044O002900012O0032000500023O0012330006000B3O00201900073O000A2O00580002000500070012330005000C3O00200400050005000D2O0032000700023O00201900083O000E00201900093O000F00063E000900310001000100044O00310001001233000900103O002019000A3O0011002019000B3O0012002019000C3O00132O00310005000C4O005E00055O00044O000200012O005A3O00017O00033O00028O00026O00F03F026O000840011C3O001233000100014O004F000200033O002653000100150001000200044O00150001002653000200040001000100044O00040001001233000400013O002653000400070001000100044O0007000100063B0003000C00013O00044O000C0001001233000300034O001600056O0016000600014O0032000700034O0049000600074O000A00056O005E00055O00044O0007000100044O0004000100044O001B0001002653000100020001000100044O00020001001233000200014O004F000300033O001233000100023O00044O000200012O005A3O00017O00103O00028O00026O00084003063O0069706169727303053O00706169727303063O00737472696E6703043O0062797465026O00F03F03053O007461626C6503063O00696E7365727403043O0063686172026O001C4003063O00636F6E6361742O033O00737562027O004003073O0072657665727365025O003DBF4001573O001233000100014O004F000200043O000E2A000200240001000100044O0024000100123A000500034O0032000600034O003000050002000700044O001D000100123A000A00044O005F000B5O00123A000C00053O002019000C000C00062O0032000D00093O001233000E00074O0046000F00094O001E000C000F4O0064000B3O00012O0030000A0002000C00044O001B000100123A000F00083O002019000F000F00092O0032001000043O00123A001100053O00201900110011000A00204C0012000E000B2O0049001100124O0029000F3O000100061D000A00130001000200044O0013000100061D000500080001000200044O0008000100123A000500083O00201900050005000C2O0032000600044O0031000500064O005E00055O002653000100420001000700044O004200012O005F00056O0032000300054O004600055O000614000200410001000500044O00410001001233000500013O000E2A0001002C0001000500044O002C000100123A000600083O0020190006000600092O0032000700033O00123A000800053O00201900080008000D2O003200095O001233000A00074O0032000B00024O001E0008000B4O002900063O000100123A000600053O00201900060006000D2O003200075O00204C0008000200072O00540006000800022O00323O00063O00044O0028000100044O002C000100044O002800010012330001000E3O0026530001004C0001000E00044O004C000100123A000500083O0020190005000500092O0032000600034O003200076O00030005000700012O005F00056O0032000400053O001233000100023O002653000100020001000100044O0002000100123A000500053O00201900050005000F2O003200066O00020005000200022O00323O00053O001233000200103O001233000100073O00044O000200012O005A3O00017O00153O00028O00026O00F03F03023O00696F03043O006F70656E03073O004D4F44522O4F5403083O00736372697074732F03043O002E6C756103053O00646562756703073O00676574696E666F030A3O006C6F6164737472696E6703013O005303063O00736F7572636503043O003D5B435D03073O007061636B61676503063O006C6F6164656403043O007265616403023O002A6103053O00636C6F736503043O006773756203023O00252E03013O002F01963O001233000100014O004F000200033O002653000100070001000100044O00070001001233000200014O004F000300033O001233000100023O002653000100020001000200044O00020001002653000200810001000200044O0081000100123A000400033O00201900040004000400123A000500053O001233000600064O003200075O001233000800074O00580005000500082O00020004000200022O0032000300043O0006610003007C00013O00044O007C0001001233000400014O004F000500063O000E2A0001001D0001000400044O001D0001001233000500014O004F000600063O001233000400023O000E2A000200180001000400044O001800010026530005001F0001000100044O001F000100123A000700083O00201900070007000900123A0008000A3O0012330009000B4O00540007000900022O0032000600073O0006610006009500013O00044O0095000100201900070006000C002653000700950001000D00044O00950001001233000700014O004F000800093O002653000700330001000100044O00330001001233000800014O004F000900093O001233000700023O0026530007002E0001000200044O002E00010026530008005F0001000200044O005F00010006610009009500013O00044O00950001001233000A00014O004F000B000C3O000E2A000200580001000A00044O00580001001233000D00013O002653000D003E0001000100044O003E0001002653000B00430001000200044O004300012O002C000C00023O002653000B003D0001000100044O003D0001001233000E00013O000E2A0001004F0001000E00044O004F00012O0032000F00094O001A000F000100022O0032000C000F3O00123A000F000E3O002019000F000F000F2O0039000F3O000C001233000E00023O000E2A000200460001000E00044O00460001001233000B00023O00044O003D000100044O0046000100044O003D000100044O003E000100044O003D000100044O00950001002653000A003B0001000100044O003B0001001233000B00014O004F000C000C3O001233000A00023O00044O003B000100044O00950001002653000800350001000100044O00350001001233000A00013O000E2A000200660001000A00044O00660001001233000800023O00044O00350001002653000A00620001000100044O0062000100123A000B000A4O0016000C5O002004000D00030010001233000F00114O001E000D000F4O000D000C6O002B000B3O00022O00320009000B3O002004000B000300122O005C000B00020001001233000A00023O00044O0062000100044O0035000100044O0095000100044O002E000100044O0095000100044O001F000100044O0095000100044O0018000100044O009500012O0016000400014O003200056O0031000400054O005E00045O00044O00950001002653000200090001000100044O0009000100200400043O0013001233000600143O001233000700154O00540004000700022O00323O00043O00123A0004000E3O00201900040004000F2O0045000400043O0006610004009100013O00044O0091000100123A0004000E3O00201900040004000F2O0045000400044O002C000400023O001233000200023O00044O0009000100044O0095000100044O000200012O005A3O00017O00133O00028O0003023O00696F03043O006F70656E03073O004D4F44522O4F5403083O00736372697074732F03043O002E6C756103013O0072026O00F03F03053O00646562756703073O00676574696E666F030A3O006C6F6164737472696E6703013O005303063O00736F7572636503043O003D5B435D03083O006C6F616466696C6503063O00474C4F42414C03043O007265616403023O002A6103053O00636C6F736503693O001233000300014O004F000400043O0026530003005F0001000100044O005F000100123A000500023O00201900050005000300123A000600043O001233000700054O003200085O001233000900064O0058000600060009001233000700074O00540005000700022O0032000400053O0006610004005E00013O00044O005E0001001233000500014O004F000600073O002653000500580001000800044O00580001002653000600140001000100044O0014000100123A000800093O00201900080008000A00123A0009000B3O001233000A000C4O00540008000A00022O0032000700083O0006610007005E00013O00044O005E000100201900080007000D0026530008005E0001000E00044O005E0001001233000800014O004F0009000A3O0026530008004E0001000800044O004E0001002653000900370001000800044O00370001000661000A005400013O00044O0054000100123A000B000F3O00123A000C00103O000665000D3O000100012O00053O000A3O001007000C000F000D2O0016000C6O0032000D6O0032000E00014O0032000F00024O0054000C000F000200123A000D00103O001007000D000F000B2O002C000C00023O00044O00540001000E2A000100250001000900044O00250001001233000B00013O002653000B00470001000100044O0047000100123A000C000B4O0016000D00013O002004000E00040011001233001000124O001E000E00104O000D000D6O002B000C3O00022O0032000A000C3O002004000C000400132O005C000C00020001001233000B00083O002653000B003A0001000800044O003A0001001233000900083O00044O0025000100044O003A000100044O0025000100044O00540001002653000800230001000100044O00230001001233000900014O004F000A000A3O001233000800083O00044O002300012O005500085O00044O005E000100044O0014000100044O005E0001002653000500120001000100044O00120001001233000600014O004F000700073O001233000500083O00044O00120001001233000300083O002653000300020001000800044O000200012O001600056O003200066O0032000700014O0032000800024O0031000500084O005E00055O00044O000200012O005A3O00013O00018O00034O00168O002C3O00024O005A3O00017O00123O00028O00026O00F03F03053O006D6174636803043O002E6C756103023O00696F03043O006F70656E03073O004D4F44522O4F5403053O00646562756703073O00676574696E666F030A3O006C6F6164737472696E6703013O005303063O00736F7572636503043O003D5B435D03043O007265616403023O002A6103053O00636C6F736503073O0073657466656E762O033O00656E7601683O001233000100014O004F000200043O002653000100610001000200044O006100012O004F000400043O002653000200210001000100044O00210001001233000500013O0026530005000C0001000200044O000C0001001233000200023O00044O00210001002653000500080001000100044O0008000100200400063O0003001233000800044O00540006000800020006610006001500013O00044O0015000100063E3O00180001000100044O001800012O003200065O001233000700044O00583O0006000700123A000600053O00201900060006000600123A000700074O003200086O00580007000700082O00020006000200022O0032000300063O001233000500023O00044O00080001002653000200050001000200044O0005000100123A000500083O00201900050005000900123A0006000A3O0012330007000B4O00540005000700022O0032000400053O0006610004006700013O00044O0067000100201900050004000C002653000500670001000D00044O00670001001233000500014O004F000600073O002653000500350001000100044O00350001001233000600014O004F000700073O001233000500023O002653000500300001000200044O003000010026530006004C0001000100044O004C0001001233000800013O000E2A0002003E0001000800044O003E0001001233000600023O00044O004C00010026530008003A0001000100044O003A000100123A0009000A4O0016000A5O002004000B0003000E001233000D000F4O001E000B000D4O000D000A6O002B00093O00022O0032000700093O0020040009000300102O005C000900020001001233000800023O00044O003A0001002653000600370001000200044O003700010006610007005700013O00044O0057000100123A000800114O0032000900073O00123A000A00124O00030008000A00012O0032000800074O004800080001000100044O006700012O0016000800014O003200096O005C00080002000100044O0067000100044O0037000100044O0067000100044O0030000100044O0067000100044O0005000100044O00670001002653000100020001000100044O00020001001233000200014O004F000300033O001233000100023O00044O000200012O005A3O00017O00",
    getfenv(), ...);
