# DontStarveLuaJIT
	Don't Starve LuaJIT optimization patch

##  NOTICE

Be sure to back up your archives, there are no guarantees that there are no bugs!

# Roadload

## Don't Starve Together

- [x] windows x64
- [ ] windows x86
- [ ] linux 
- [ ] macos
- [ ] andorid
- [ ] switch

## Don't Starve 

- [ ] windows x64
- [ ] windows x86
- [ ] linux 
- [ ] macos
- [ ] andorid
- [ ] switch


## Installation: 

### Windows

	Copy all files to the bin64 folder in the game directory

	like: C:\\steamapps\\Don't Starve Together\\bin64\
	
	Launch the game, press ` and type:
	
	print(_Version)
	
	And you can see message started with "LuaJIT".

## How to debug game:

### vscode launch.json
```json
  {
        "address": "127.0.0.1:12306",
        "name": "attach",
        "request": "attach",
        "stopOnEntry": true,
        "type": "lua",
        "luaVersion": "luajit",
        "client": false
      }
```

### data/scripts/main.lua:
```lua
DEBUGGER_ENABLED = TheSim:ShouldInitDebugger() and IsNotConsole() and CONFIGURATION ~= "PRODUCTION" and not TheNet:IsDedicated()
if DEBUGGER_ENABLED then
	Debuggee = require 'debuggee'
end
-- new debugger
local function dofile(filename)
	local load = _VERSION == "Lua 5.1" and loadstring or load
	local f = assert(io.open(filename))
	local str = f:read "*a"
	f:close()
	return assert(load(str, "=(debugger.lua)"))(filename)
end
if jit then
	local path = "C:/Users/fesil/.vscode/extensions/actboy168.lua-debug-2.0.4-win32-x64"
	local debugger = dofile(path .. "/script/debugger.lua")
	Debuggee = {}
	Debuggee.start = function ()
		local host = {address = "127.0.0.1:12306", client= true}
		debugger:start(host):event ("autoUpdate", false)
		return "ok", host
	end
	Debuggee.poll = function ()
		debugger:event "update"
	end
	DEBUGGER_ENABLED = true
end
```