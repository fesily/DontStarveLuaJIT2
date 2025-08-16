-- Use this file to enable and configure your mods. The mod will only be available in the game
-- if you set "enabled=true"!!!
--
-- Also, during the container startup this file will be copied to both Master/ and Caves/ folders. What's setup here
-- will be available in both shards!
--
-- See the example below:

return {
  ["workshop-3322803908"]={
    configuration_options={
     },
    enabled=true 
  },
  ["luajit2"]={
    configuration_options={
      ["EnabledJIT"]=true,
      ["DisableForceFullGC"]=64,
      ["EnableFrameGC"]=3,
      ["TargetLogicFPS"]=30,
      ["TargetRenderFPS"]=false,
      ["JitOpt"]=true,
      ["ModBlackList"]=true,
      ["DisableJITWhenServer"]=false,
      ["EnableProfiler"]="off",
      ["EnableTracy"]="off"
    },
    enabled=true 
  },
}