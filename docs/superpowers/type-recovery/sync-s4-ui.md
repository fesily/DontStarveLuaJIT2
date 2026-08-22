# sync-s4-ui — Phase 0 layout dump (UI/输入)

program: `dontstarve_steam` (macOS i386)
source: ghidra-mcp get_struct_layout (read-only)
rule: Size=1 placeholder / not-a-struct / not-found → exists: false

## Summary
- processed: 41
- exists: 16
- missing/placeholder: 25

## Layouts

### WindowManager
size: 136 (hex 0x88)
exists: true
layout:
  0 | void * | pVtable
  4 | byte[120] | pField_0x04
  124 | byte[12] | pField_0x7C

### cUIScreen
size: 12 (hex 0xC)
exists: true
layout:
  0 | void * | pVtable
  4 | byte[4] | pM_strName
  8 | void * | pGame

### cBootScreen
size: 12 (hex 0xC)
exists: true
layout:
  0 | cUIScreen | base

### cGameScreen
size: 16 (hex 0x10)
exists: true
layout:
  0 | cUIScreen | base
  12 | void * | pGame

### cImageWidget
size: 24 (hex 0x18)
exists: true
layout:
  0 | cEntityComponent | base
  16 | void * | pVtable2
  20 | void * | pImageObj

### cVideoWidget
size: 24 (hex 0x18)
exists: true
layout:
  0 | cEntityComponent | base
  16 | void * | pVtable2
  20 | void * | pVideoObj

### cTextWidget
size: 20 (hex 0x14)
exists: true
layout:
  0 | cEntityComponent | base
  16 | void * | pTextObj

### cTextEditWidget
size: 1 (hex 0x1)
exists: false

### cClientColourPicker
size: 40 (hex 0x28)
exists: true
layout:
  0 | byte[24] | pMap_colour
  24 | byte[12] | pVecColours
  36 | byte[4] | pColour

### cConsoleInput
size: 220 (hex 0xDC)
exists: true
layout:
  0 | byte[120] | pThread
  120 | byte[4] | pM_strName
  124 | byte[40] | pDeque
  164 | Mutex | Mutex

### cLineEditor
size: 1028 (hex 0x404)
exists: true
layout:
  0 | char[1000] | pSBuffer
  1000 | int | nCursorPos
  1004 | int | nLength
  1008 | int | nHistoryCount
  1012 | bool | fInsertMode
  1016 | void * | pVecHistory_begin
  1020 | void * | pVecHistory_end
  1024 | void * | pVecHistory_cap

### DontStarveInputHandler
size: 720 (hex 0x2D0)
exists: true
layout:
  0 | void * | pVptr
  4 | void * | pStateObj
  8 | void * | pInputManager
  12 | void * | pGameEventDispatcher
  16 | void * | pLuaCallTarget
  20 | void * | pLuaState
  24 | byte[16] | pMInitVec
  40 | int | nRefOnInputKey
  44 | int | nRefOnMouseButton
  48 | int | nRefOnMouseMove
  52 | byte[12] | pVecControls
  64 | int | nField_0x40
  481 | byte[6] | pWheelState
  578 | byte[3] | pState
  584 | byte[124] | pOMappingStorage
  708 | int | nTail_0x2C4
  712 | int | nTail_0x2C8
  716 | int | nTail_0x2CC

### ControlMapper
size: 520 (hex 0x208)
exists: true
layout:
  0 | void * | pInputManager
  4 | ushort | wField
  8 | void * | pGlobal
  12 | int | nControlCount
  16 | int | nField_0x10
  20 | void * | pMappingStorage2
  28 | void * | pInputManager2
  36 | int | nField_0x24
  40 | byte | bField_0x28
  44 | void * | pSelf
  48 | void * | pGlobal2
  52 | int | nField_0x34
  56 | int | nField_0x38
  60 | int | nField_0x3C
  64 | int | nField_0x40
  68 | byte[452] | pUNKNOWN_0x44

### Control
size: 16 (hex 0x10)
exists: true
layout:
  0 | uint | dwId
  4 | uint | dwType
  8 | uint | dwInput
  12 | uint | dwInput2

### InputMapping
size: 1 (hex 0x1)
exists: false

### IInputDevice
size: 1 (hex 0x1)
exists: false

### IInputManager
size: 1 (hex 0x1)
exists: false

### SDLInputManager
size: 1 (hex 0x1)
exists: false

### SDLInputDevice
size: 1 (hex 0x1)
exists: false

### KeyboardMouseDevice
size: 1 (hex 0x1)
exists: false

### SteamInputDevice
size: 1 (hex 0x1)
exists: false

### BaseInput
size: 1 (hex 0x1)
exists: false

### DigitalControl
size: 1 (hex 0x1)
exists: false

### DigitalInput
size: 1 (hex 0x1)
exists: false

### AnalogControl
size: 1 (hex 0x1)
exists: false

### AnalogInput
size: 1 (hex 0x1)
exists: false

### JoystickKey
size: 1 (hex 0x1)
exists: false
note: Demangler type /Demangler/Input/JoystickKey; not a structure; get_type_size=1

### Vibrator
size: 1 (hex 0x1)
exists: false

### Vibration
size: 1 (hex 0x1)
exists: false

### AxisInfo
size: 1 (hex 0x1)
exists: false

### cUnpackModThread
size: 424 (hex 0x1A8)
exists: true
layout:
  0 | byte[120] | pThread
  120 | byte[12] | pStrs
  132 | byte[288] | pUgcResult
  420 | void * | pWorkshop

### cWorkshopModHelper
size: 0 (hex 0x0)
exists: false
note: Structure not found; search_data_types empty

### FontComponent
size: 16 (hex 0x10)
exists: true
layout:
  0 | cEntityComponent | base

### PurchasesManagerComponent
size: 16 (hex 0x10)
exists: true
layout:
  0 | void * | pVtable
  4 | byte[12] | pVecStrings

### cTextWidgetProxy
size: 0 (hex 0x0)
exists: false
note: Structure not found; demangler has TextWidgetProxy (size 1)

### TextEditWidgetProxy
size: 1 (hex 0x1)
exists: false

### ImageWidgetProxy
size: 1 (hex 0x1)
exists: false

### VideoWidgetProxy
size: 1 (hex 0x1)
exists: false

### FontComponentProxy
size: 1 (hex 0x1)
exists: false

### WidgetProxy
size: 0 (hex 0x0)
exists: false
note: Structure not found

### UIWidgetLuaProxy
size: 0 (hex 0x0)
exists: false
note: Structure not found; search_data_types UIWidget empty

## Exists list (16)
WindowManager, cUIScreen, cBootScreen, cGameScreen, cImageWidget, cVideoWidget, cTextWidget, cClientColourPicker, cConsoleInput, cLineEditor, DontStarveInputHandler, ControlMapper, Control, cUnpackModThread, FontComponent, PurchasesManagerComponent

## Missing/placeholder list (25)
cTextEditWidget, InputMapping, IInputDevice, IInputManager, SDLInputManager, SDLInputDevice, KeyboardMouseDevice, SteamInputDevice, BaseInput, DigitalControl, DigitalInput, AnalogControl, AnalogInput, JoystickKey, Vibrator, Vibration, AxisInfo, cWorkshopModHelper, cTextWidgetProxy, TextEditWidgetProxy, ImageWidgetProxy, VideoWidgetProxy, FontComponentProxy, WidgetProxy, UIWidgetLuaProxy
