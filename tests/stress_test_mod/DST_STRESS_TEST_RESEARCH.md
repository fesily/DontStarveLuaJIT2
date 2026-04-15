# Don't Starve Together Bot Framework Research
## Comprehensive API & Architecture Analysis

**Research Date**: April 2026  
**Scope**: DST Lua API for automated player behavior, bot mods, and stress testing infrastructure  

---

## 1. CORE ACTION SYSTEM (Player Behavior Foundation)

### 1.1 BufferedAction Class
**File**: `bufferedaction.lua` (109 lines)  
**Purpose**: Encapsulates a queued player action (chop, attack, cook, equip, etc.)

```lua
BufferedAction = Class(function(self, doer, target, action, invobject, pos, recipe, distance, forced, rotation, arrivedist)
    self.doer = doer                           -- Entity performing action (player)
    self.target = target                       -- Entity being acted upon
    self.action = action                       -- Action type (CHOP, ATTACK, COOK, etc.)
    self.invobject = invobject                 -- Item in inventory used for action
    self.pos = pos ~= nil and DynamicPosition(pos) or nil  -- Position to act at
    self.recipe = recipe                       -- For crafting actions
    self.distance = distance or action.distance  -- Required distance from target
    self.arrivedist = arrivedist or action.arrivedist  -- Distance at which to stop moving
    self.forced = forced                       -- Force action execution
    self.rotation = rotation or 0              -- Facing angle
    self.onsuccess = {}                        -- Callbacks on success
    self.onfail = {}                           -- Callbacks on failure
end)
```

---

## 2. ACTION SYSTEM (ACTIONS table)

```lua
ACTIONS = {
    WALKTO = Action({ priority=-4, ghost_valid=true }),
    CHOP = Action({ distance=1.75 }),
    PICK = Action({ canforce=true }),
    ATTACK = Action({ priority=2, canforce=true }),
    COOK = Action({ priority=1 }),
    CRAFT = Action(),
    BUILD = Action(),
    PLANT = Action(),
    EQUIP = Action({ priority=0, instant=true }),
    UNEQUIP = Action({ priority=-2, instant=true }),
    DROP = Action({ priority=-1 }),
    EAT = Action(),
    -- ... 50+ more actions
}
```

---

## 3. BRAIN SYSTEM

### BrainManager Pattern
```lua
BrainWrangler:AddInstance(brain)          -- Register brain
BrainWrangler:RemoveInstance(brain)       -- Unregister
BrainWrangler:Wake(brain)                 -- Activate
BrainWrangler:Hibernate(brain)            -- Sleep
BrainWrangler:Sleep(brain, time)          -- Sleep until tick
```

---

## 4. BEHAVIOR TREES

Available behaviors:
- Approach, ChaseAndAttack, Wander, FindEntity, RunAway, FaceEntity, DoAction, etc.

---

## 5. CONSOLE COMMANDS

```lua
c_godmode()                 -- Invincible
c_spawn("tree", 5)          -- Spawn trees
c_give("axe")               -- Give item
c_sethunger(100)            -- Set hunger
c_skip(1)                   -- Skip 1 day
c_remote("Lua code")        -- Execute on server
```

---

## IMPLEMENTATION ROADMAP

### Phase 1: PoC (1-2 days)
- Simple farming loop with BufferedAction
- Single instance test
- Verify action queueing

### Phase 2: Multi-Instance (2-3 days)
- Process spawner
- IPC layer
- Bot coordination

### Phase 3: Advanced Behaviors (3-5 days)
- Custom Brain for players
- Behavior tree nodes
- State persistence

### Phase 4: Stress Testing (2-3 days)
- Test scenarios
- Metrics collection
- Performance baseline

---

**Status**: Research Complete - Ready for Implementation
