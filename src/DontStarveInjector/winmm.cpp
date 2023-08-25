
//
// created by AheadLib
// github:https://github.com/strivexjun/AheadLib-x86-x64
//

#include <windows.h>
#include <TCHAR.h>
#include <string>
#include <atomic>
#include <unordered_map>
#include <thread>
#include <format>
#include <shellapi.h>
#include <ShlObj.h>
#include "module.hpp"

using namespace std::literals;

#pragma comment(linker, "/EXPORT:Noname2=AheadLib_Unnamed2,@2,NONAME")
#pragma comment(linker, "/EXPORT:mciExecute=AheadLib_mciExecute,@3")
#pragma comment(linker, "/EXPORT:CloseDriver=AheadLib_CloseDriver,@4")
#pragma comment(linker, "/EXPORT:DefDriverProc=AheadLib_DefDriverProc,@5")
#pragma comment(linker, "/EXPORT:DriverCallback=AheadLib_DriverCallback,@6")
#pragma comment(linker, "/EXPORT:DrvGetModuleHandle=AheadLib_DrvGetModuleHandle,@7")
#pragma comment(linker, "/EXPORT:GetDriverModuleHandle=AheadLib_GetDriverModuleHandle,@8")
#pragma comment(linker, "/EXPORT:OpenDriver=AheadLib_OpenDriver,@9")
#pragma comment(linker, "/EXPORT:PlaySound=AheadLib_PlaySound,@10")
#pragma comment(linker, "/EXPORT:PlaySoundA=AheadLib_PlaySoundA,@11")
#pragma comment(linker, "/EXPORT:PlaySoundW=AheadLib_PlaySoundW,@12")
#pragma comment(linker, "/EXPORT:SendDriverMessage=AheadLib_SendDriverMessage,@13")
#pragma comment(linker, "/EXPORT:WOWAppExit=AheadLib_WOWAppExit,@14")
#pragma comment(linker, "/EXPORT:auxGetDevCapsA=AheadLib_auxGetDevCapsA,@15")
#pragma comment(linker, "/EXPORT:auxGetDevCapsW=AheadLib_auxGetDevCapsW,@16")
#pragma comment(linker, "/EXPORT:auxGetNumDevs=AheadLib_auxGetNumDevs,@17")
#pragma comment(linker, "/EXPORT:auxGetVolume=AheadLib_auxGetVolume,@18")
#pragma comment(linker, "/EXPORT:auxOutMessage=AheadLib_auxOutMessage,@19")
#pragma comment(linker, "/EXPORT:auxSetVolume=AheadLib_auxSetVolume,@20")
#pragma comment(linker, "/EXPORT:joyConfigChanged=AheadLib_joyConfigChanged,@21")
#pragma comment(linker, "/EXPORT:joyGetDevCapsA=AheadLib_joyGetDevCapsA,@22")
#pragma comment(linker, "/EXPORT:joyGetDevCapsW=AheadLib_joyGetDevCapsW,@23")
#pragma comment(linker, "/EXPORT:joyGetNumDevs=AheadLib_joyGetNumDevs,@24")
#pragma comment(linker, "/EXPORT:joyGetPos=AheadLib_joyGetPos,@25")
#pragma comment(linker, "/EXPORT:joyGetPosEx=AheadLib_joyGetPosEx,@26")
#pragma comment(linker, "/EXPORT:joyGetThreshold=AheadLib_joyGetThreshold,@27")
#pragma comment(linker, "/EXPORT:joyReleaseCapture=AheadLib_joyReleaseCapture,@28")
#pragma comment(linker, "/EXPORT:joySetCapture=AheadLib_joySetCapture,@29")
#pragma comment(linker, "/EXPORT:joySetThreshold=AheadLib_joySetThreshold,@30")
#pragma comment(linker, "/EXPORT:mciDriverNotify=AheadLib_mciDriverNotify,@31")
#pragma comment(linker, "/EXPORT:mciDriverYield=AheadLib_mciDriverYield,@32")
#pragma comment(linker, "/EXPORT:mciFreeCommandResource=AheadLib_mciFreeCommandResource,@33")
#pragma comment(linker, "/EXPORT:mciGetCreatorTask=AheadLib_mciGetCreatorTask,@34")
#pragma comment(linker, "/EXPORT:mciGetDeviceIDA=AheadLib_mciGetDeviceIDA,@35")
#pragma comment(linker, "/EXPORT:mciGetDeviceIDFromElementIDA=AheadLib_mciGetDeviceIDFromElementIDA,@36")
#pragma comment(linker, "/EXPORT:mciGetDeviceIDFromElementIDW=AheadLib_mciGetDeviceIDFromElementIDW,@37")
#pragma comment(linker, "/EXPORT:mciGetDeviceIDW=AheadLib_mciGetDeviceIDW,@38")
#pragma comment(linker, "/EXPORT:mciGetDriverData=AheadLib_mciGetDriverData,@39")
#pragma comment(linker, "/EXPORT:mciGetErrorStringA=AheadLib_mciGetErrorStringA,@40")
#pragma comment(linker, "/EXPORT:mciGetErrorStringW=AheadLib_mciGetErrorStringW,@41")
#pragma comment(linker, "/EXPORT:mciGetYieldProc=AheadLib_mciGetYieldProc,@42")
#pragma comment(linker, "/EXPORT:mciLoadCommandResource=AheadLib_mciLoadCommandResource,@43")
#pragma comment(linker, "/EXPORT:mciSendCommandA=AheadLib_mciSendCommandA,@44")
#pragma comment(linker, "/EXPORT:mciSendCommandW=AheadLib_mciSendCommandW,@45")
#pragma comment(linker, "/EXPORT:mciSendStringA=AheadLib_mciSendStringA,@46")
#pragma comment(linker, "/EXPORT:mciSendStringW=AheadLib_mciSendStringW,@47")
#pragma comment(linker, "/EXPORT:mciSetDriverData=AheadLib_mciSetDriverData,@48")
#pragma comment(linker, "/EXPORT:mciSetYieldProc=AheadLib_mciSetYieldProc,@49")
#pragma comment(linker, "/EXPORT:midiConnect=AheadLib_midiConnect,@50")
#pragma comment(linker, "/EXPORT:midiDisconnect=AheadLib_midiDisconnect,@51")
#pragma comment(linker, "/EXPORT:midiInAddBuffer=AheadLib_midiInAddBuffer,@52")
#pragma comment(linker, "/EXPORT:midiInClose=AheadLib_midiInClose,@53")
#pragma comment(linker, "/EXPORT:midiInGetDevCapsA=AheadLib_midiInGetDevCapsA,@54")
#pragma comment(linker, "/EXPORT:midiInGetDevCapsW=AheadLib_midiInGetDevCapsW,@55")
#pragma comment(linker, "/EXPORT:midiInGetErrorTextA=AheadLib_midiInGetErrorTextA,@56")
#pragma comment(linker, "/EXPORT:midiInGetErrorTextW=AheadLib_midiInGetErrorTextW,@57")
#pragma comment(linker, "/EXPORT:midiInGetID=AheadLib_midiInGetID,@58")
#pragma comment(linker, "/EXPORT:midiInGetNumDevs=AheadLib_midiInGetNumDevs,@59")
#pragma comment(linker, "/EXPORT:midiInMessage=AheadLib_midiInMessage,@60")
#pragma comment(linker, "/EXPORT:midiInOpen=AheadLib_midiInOpen,@61")
#pragma comment(linker, "/EXPORT:midiInPrepareHeader=AheadLib_midiInPrepareHeader,@62")
#pragma comment(linker, "/EXPORT:midiInReset=AheadLib_midiInReset,@63")
#pragma comment(linker, "/EXPORT:midiInStart=AheadLib_midiInStart,@64")
#pragma comment(linker, "/EXPORT:midiInStop=AheadLib_midiInStop,@65")
#pragma comment(linker, "/EXPORT:midiInUnprepareHeader=AheadLib_midiInUnprepareHeader,@66")
#pragma comment(linker, "/EXPORT:midiOutCacheDrumPatches=AheadLib_midiOutCacheDrumPatches,@67")
#pragma comment(linker, "/EXPORT:midiOutCachePatches=AheadLib_midiOutCachePatches,@68")
#pragma comment(linker, "/EXPORT:midiOutClose=AheadLib_midiOutClose,@69")
#pragma comment(linker, "/EXPORT:midiOutGetDevCapsA=AheadLib_midiOutGetDevCapsA,@70")
#pragma comment(linker, "/EXPORT:midiOutGetDevCapsW=AheadLib_midiOutGetDevCapsW,@71")
#pragma comment(linker, "/EXPORT:midiOutGetErrorTextA=AheadLib_midiOutGetErrorTextA,@72")
#pragma comment(linker, "/EXPORT:midiOutGetErrorTextW=AheadLib_midiOutGetErrorTextW,@73")
#pragma comment(linker, "/EXPORT:midiOutGetID=AheadLib_midiOutGetID,@74")
#pragma comment(linker, "/EXPORT:midiOutGetNumDevs=AheadLib_midiOutGetNumDevs,@75")
#pragma comment(linker, "/EXPORT:midiOutGetVolume=AheadLib_midiOutGetVolume,@76")
#pragma comment(linker, "/EXPORT:midiOutLongMsg=AheadLib_midiOutLongMsg,@77")
#pragma comment(linker, "/EXPORT:midiOutMessage=AheadLib_midiOutMessage,@78")
#pragma comment(linker, "/EXPORT:midiOutOpen=AheadLib_midiOutOpen,@79")
#pragma comment(linker, "/EXPORT:midiOutPrepareHeader=AheadLib_midiOutPrepareHeader,@80")
#pragma comment(linker, "/EXPORT:midiOutReset=AheadLib_midiOutReset,@81")
#pragma comment(linker, "/EXPORT:midiOutSetVolume=AheadLib_midiOutSetVolume,@82")
#pragma comment(linker, "/EXPORT:midiOutShortMsg=AheadLib_midiOutShortMsg,@83")
#pragma comment(linker, "/EXPORT:midiOutUnprepareHeader=AheadLib_midiOutUnprepareHeader,@84")
#pragma comment(linker, "/EXPORT:midiStreamClose=AheadLib_midiStreamClose,@85")
#pragma comment(linker, "/EXPORT:midiStreamOpen=AheadLib_midiStreamOpen,@86")
#pragma comment(linker, "/EXPORT:midiStreamOut=AheadLib_midiStreamOut,@87")
#pragma comment(linker, "/EXPORT:midiStreamPause=AheadLib_midiStreamPause,@88")
#pragma comment(linker, "/EXPORT:midiStreamPosition=AheadLib_midiStreamPosition,@89")
#pragma comment(linker, "/EXPORT:midiStreamProperty=AheadLib_midiStreamProperty,@90")
#pragma comment(linker, "/EXPORT:midiStreamRestart=AheadLib_midiStreamRestart,@91")
#pragma comment(linker, "/EXPORT:midiStreamStop=AheadLib_midiStreamStop,@92")
#pragma comment(linker, "/EXPORT:mixerClose=AheadLib_mixerClose,@93")
#pragma comment(linker, "/EXPORT:mixerGetControlDetailsA=AheadLib_mixerGetControlDetailsA,@94")
#pragma comment(linker, "/EXPORT:mixerGetControlDetailsW=AheadLib_mixerGetControlDetailsW,@95")
#pragma comment(linker, "/EXPORT:mixerGetDevCapsA=AheadLib_mixerGetDevCapsA,@96")
#pragma comment(linker, "/EXPORT:mixerGetDevCapsW=AheadLib_mixerGetDevCapsW,@97")
#pragma comment(linker, "/EXPORT:mixerGetID=AheadLib_mixerGetID,@98")
#pragma comment(linker, "/EXPORT:mixerGetLineControlsA=AheadLib_mixerGetLineControlsA,@99")
#pragma comment(linker, "/EXPORT:mixerGetLineControlsW=AheadLib_mixerGetLineControlsW,@100")
#pragma comment(linker, "/EXPORT:mixerGetLineInfoA=AheadLib_mixerGetLineInfoA,@101")
#pragma comment(linker, "/EXPORT:mixerGetLineInfoW=AheadLib_mixerGetLineInfoW,@102")
#pragma comment(linker, "/EXPORT:mixerGetNumDevs=AheadLib_mixerGetNumDevs,@103")
#pragma comment(linker, "/EXPORT:mixerMessage=AheadLib_mixerMessage,@104")
#pragma comment(linker, "/EXPORT:mixerOpen=AheadLib_mixerOpen,@105")
#pragma comment(linker, "/EXPORT:mixerSetControlDetails=AheadLib_mixerSetControlDetails,@106")
#pragma comment(linker, "/EXPORT:mmDrvInstall=AheadLib_mmDrvInstall,@107")
#pragma comment(linker, "/EXPORT:mmGetCurrentTask=AheadLib_mmGetCurrentTask,@108")
#pragma comment(linker, "/EXPORT:mmTaskBlock=AheadLib_mmTaskBlock,@109")
#pragma comment(linker, "/EXPORT:mmTaskCreate=AheadLib_mmTaskCreate,@110")
#pragma comment(linker, "/EXPORT:mmTaskSignal=AheadLib_mmTaskSignal,@111")
#pragma comment(linker, "/EXPORT:mmTaskYield=AheadLib_mmTaskYield,@112")
#pragma comment(linker, "/EXPORT:mmioAdvance=AheadLib_mmioAdvance,@113")
#pragma comment(linker, "/EXPORT:mmioAscend=AheadLib_mmioAscend,@114")
#pragma comment(linker, "/EXPORT:mmioClose=AheadLib_mmioClose,@115")
#pragma comment(linker, "/EXPORT:mmioCreateChunk=AheadLib_mmioCreateChunk,@116")
#pragma comment(linker, "/EXPORT:mmioDescend=AheadLib_mmioDescend,@117")
#pragma comment(linker, "/EXPORT:mmioFlush=AheadLib_mmioFlush,@118")
#pragma comment(linker, "/EXPORT:mmioGetInfo=AheadLib_mmioGetInfo,@119")
#pragma comment(linker, "/EXPORT:mmioInstallIOProcA=AheadLib_mmioInstallIOProcA,@120")
#pragma comment(linker, "/EXPORT:mmioInstallIOProcW=AheadLib_mmioInstallIOProcW,@121")
#pragma comment(linker, "/EXPORT:mmioOpenA=AheadLib_mmioOpenA,@122")
#pragma comment(linker, "/EXPORT:mmioOpenW=AheadLib_mmioOpenW,@123")
#pragma comment(linker, "/EXPORT:mmioRead=AheadLib_mmioRead,@124")
#pragma comment(linker, "/EXPORT:mmioRenameA=AheadLib_mmioRenameA,@125")
#pragma comment(linker, "/EXPORT:mmioRenameW=AheadLib_mmioRenameW,@126")
#pragma comment(linker, "/EXPORT:mmioSeek=AheadLib_mmioSeek,@127")
#pragma comment(linker, "/EXPORT:mmioSendMessage=AheadLib_mmioSendMessage,@128")
#pragma comment(linker, "/EXPORT:mmioSetBuffer=AheadLib_mmioSetBuffer,@129")
#pragma comment(linker, "/EXPORT:mmioSetInfo=AheadLib_mmioSetInfo,@130")
#pragma comment(linker, "/EXPORT:mmioStringToFOURCCA=AheadLib_mmioStringToFOURCCA,@131")
#pragma comment(linker, "/EXPORT:mmioStringToFOURCCW=AheadLib_mmioStringToFOURCCW,@132")
#pragma comment(linker, "/EXPORT:mmioWrite=AheadLib_mmioWrite,@133")
#pragma comment(linker, "/EXPORT:mmsystemGetVersion=AheadLib_mmsystemGetVersion,@134")
#pragma comment(linker, "/EXPORT:sndPlaySoundA=AheadLib_sndPlaySoundA,@135")
#pragma comment(linker, "/EXPORT:sndPlaySoundW=AheadLib_sndPlaySoundW,@136")
#pragma comment(linker, "/EXPORT:timeBeginPeriod=AheadLib_timeBeginPeriod,@137")
#pragma comment(linker, "/EXPORT:timeEndPeriod=AheadLib_timeEndPeriod,@138")
#pragma comment(linker, "/EXPORT:timeGetDevCaps=AheadLib_timeGetDevCaps,@139")
#pragma comment(linker, "/EXPORT:timeGetSystemTime=AheadLib_timeGetSystemTime,@140")
#pragma comment(linker, "/EXPORT:timeGetTime=AheadLib_timeGetTime,@141")
#pragma comment(linker, "/EXPORT:timeKillEvent=AheadLib_timeKillEvent,@142")
#pragma comment(linker, "/EXPORT:timeSetEvent=AheadLib_timeSetEvent,@143")
#pragma comment(linker, "/EXPORT:waveInAddBuffer=AheadLib_waveInAddBuffer,@144")
#pragma comment(linker, "/EXPORT:waveInClose=AheadLib_waveInClose,@145")
#pragma comment(linker, "/EXPORT:waveInGetDevCapsA=AheadLib_waveInGetDevCapsA,@146")
#pragma comment(linker, "/EXPORT:waveInGetDevCapsW=AheadLib_waveInGetDevCapsW,@147")
#pragma comment(linker, "/EXPORT:waveInGetErrorTextA=AheadLib_waveInGetErrorTextA,@148")
#pragma comment(linker, "/EXPORT:waveInGetErrorTextW=AheadLib_waveInGetErrorTextW,@149")
#pragma comment(linker, "/EXPORT:waveInGetID=AheadLib_waveInGetID,@150")
#pragma comment(linker, "/EXPORT:waveInGetNumDevs=AheadLib_waveInGetNumDevs,@151")
#pragma comment(linker, "/EXPORT:waveInGetPosition=AheadLib_waveInGetPosition,@152")
#pragma comment(linker, "/EXPORT:waveInMessage=AheadLib_waveInMessage,@153")
#pragma comment(linker, "/EXPORT:waveInOpen=AheadLib_waveInOpen,@154")
#pragma comment(linker, "/EXPORT:waveInPrepareHeader=AheadLib_waveInPrepareHeader,@155")
#pragma comment(linker, "/EXPORT:waveInReset=AheadLib_waveInReset,@156")
#pragma comment(linker, "/EXPORT:waveInStart=AheadLib_waveInStart,@157")
#pragma comment(linker, "/EXPORT:waveInStop=AheadLib_waveInStop,@158")
#pragma comment(linker, "/EXPORT:waveInUnprepareHeader=AheadLib_waveInUnprepareHeader,@159")
#pragma comment(linker, "/EXPORT:waveOutBreakLoop=AheadLib_waveOutBreakLoop,@160")
#pragma comment(linker, "/EXPORT:waveOutClose=AheadLib_waveOutClose,@161")
#pragma comment(linker, "/EXPORT:waveOutGetDevCapsA=AheadLib_waveOutGetDevCapsA,@162")
#pragma comment(linker, "/EXPORT:waveOutGetDevCapsW=AheadLib_waveOutGetDevCapsW,@163")
#pragma comment(linker, "/EXPORT:waveOutGetErrorTextA=AheadLib_waveOutGetErrorTextA,@164")
#pragma comment(linker, "/EXPORT:waveOutGetErrorTextW=AheadLib_waveOutGetErrorTextW,@165")
#pragma comment(linker, "/EXPORT:waveOutGetID=AheadLib_waveOutGetID,@166")
#pragma comment(linker, "/EXPORT:waveOutGetNumDevs=AheadLib_waveOutGetNumDevs,@167")
#pragma comment(linker, "/EXPORT:waveOutGetPitch=AheadLib_waveOutGetPitch,@168")
#pragma comment(linker, "/EXPORT:waveOutGetPlaybackRate=AheadLib_waveOutGetPlaybackRate,@169")
#pragma comment(linker, "/EXPORT:waveOutGetPosition=AheadLib_waveOutGetPosition,@170")
#pragma comment(linker, "/EXPORT:waveOutGetVolume=AheadLib_waveOutGetVolume,@171")
#pragma comment(linker, "/EXPORT:waveOutMessage=AheadLib_waveOutMessage,@172")
#pragma comment(linker, "/EXPORT:waveOutOpen=AheadLib_waveOutOpen,@173")
#pragma comment(linker, "/EXPORT:waveOutPause=AheadLib_waveOutPause,@174")
#pragma comment(linker, "/EXPORT:waveOutPrepareHeader=AheadLib_waveOutPrepareHeader,@175")
#pragma comment(linker, "/EXPORT:waveOutReset=AheadLib_waveOutReset,@176")
#pragma comment(linker, "/EXPORT:waveOutRestart=AheadLib_waveOutRestart,@177")
#pragma comment(linker, "/EXPORT:waveOutSetPitch=AheadLib_waveOutSetPitch,@178")
#pragma comment(linker, "/EXPORT:waveOutSetPlaybackRate=AheadLib_waveOutSetPlaybackRate,@179")
#pragma comment(linker, "/EXPORT:waveOutSetVolume=AheadLib_waveOutSetVolume,@180")
#pragma comment(linker, "/EXPORT:waveOutUnprepareHeader=AheadLib_waveOutUnprepareHeader,@181")
#pragma comment(linker, "/EXPORT:waveOutWrite=AheadLib_waveOutWrite,@182")

static HMODULE g_OldModule = NULL;

#define FUNCTIONS(_)                \
	_(mciExecute)                   \
	_(CloseDriver)                  \
	_(DefDriverProc)                \
	_(DriverCallback)               \
	_(DrvGetModuleHandle)           \
	_(GetDriverModuleHandle)        \
	_(OpenDriver)                   \
	_(PlaySound)                    \
	_(PlaySoundA)                   \
	_(PlaySoundW)                   \
	_(SendDriverMessage)            \
	_(WOWAppExit)                   \
	_(auxGetDevCapsA)               \
	_(auxGetDevCapsW)               \
	_(auxGetNumDevs)                \
	_(auxGetVolume)                 \
	_(auxOutMessage)                \
	_(auxSetVolume)                 \
	_(joyConfigChanged)             \
	_(joyGetDevCapsA)               \
	_(joyGetDevCapsW)               \
	_(joyGetNumDevs)                \
	_(joyGetPos)                    \
	_(joyGetPosEx)                  \
	_(joyGetThreshold)              \
	_(joyReleaseCapture)            \
	_(joySetCapture)                \
	_(joySetThreshold)              \
	_(mciDriverNotify)              \
	_(mciDriverYield)               \
	_(mciFreeCommandResource)       \
	_(mciGetCreatorTask)            \
	_(mciGetDeviceIDA)              \
	_(mciGetDeviceIDFromElementIDA) \
	_(mciGetDeviceIDFromElementIDW) \
	_(mciGetDeviceIDW)              \
	_(mciGetDriverData)             \
	_(mciGetErrorStringA)           \
	_(mciGetErrorStringW)           \
	_(mciGetYieldProc)              \
	_(mciLoadCommandResource)       \
	_(mciSendCommandA)              \
	_(mciSendCommandW)              \
	_(mciSendStringA)               \
	_(mciSendStringW)               \
	_(mciSetDriverData)             \
	_(mciSetYieldProc)              \
	_(midiConnect)                  \
	_(midiDisconnect)               \
	_(midiInAddBuffer)              \
	_(midiInClose)                  \
	_(midiInGetDevCapsA)            \
	_(midiInGetDevCapsW)            \
	_(midiInGetErrorTextA)          \
	_(midiInGetErrorTextW)          \
	_(midiInGetID)                  \
	_(midiInGetNumDevs)             \
	_(midiInMessage)                \
	_(midiInOpen)                   \
	_(midiInPrepareHeader)          \
	_(midiInReset)                  \
	_(midiInStart)                  \
	_(midiInStop)                   \
	_(midiInUnprepareHeader)        \
	_(midiOutCacheDrumPatches)      \
	_(midiOutCachePatches)          \
	_(midiOutClose)                 \
	_(midiOutGetDevCapsA)           \
	_(midiOutGetDevCapsW)           \
	_(midiOutGetErrorTextA)         \
	_(midiOutGetErrorTextW)         \
	_(midiOutGetID)                 \
	_(midiOutGetNumDevs)            \
	_(midiOutGetVolume)             \
	_(midiOutLongMsg)               \
	_(midiOutMessage)               \
	_(midiOutOpen)                  \
	_(midiOutPrepareHeader)         \
	_(midiOutReset)                 \
	_(midiOutSetVolume)             \
	_(midiOutShortMsg)              \
	_(midiOutUnprepareHeader)       \
	_(midiStreamClose)              \
	_(midiStreamOpen)               \
	_(midiStreamOut)                \
	_(midiStreamPause)              \
	_(midiStreamPosition)           \
	_(midiStreamProperty)           \
	_(midiStreamRestart)            \
	_(midiStreamStop)               \
	_(mixerClose)                   \
	_(mixerGetControlDetailsA)      \
	_(mixerGetControlDetailsW)      \
	_(mixerGetDevCapsA)             \
	_(mixerGetDevCapsW)             \
	_(mixerGetID)                   \
	_(mixerGetLineControlsA)        \
	_(mixerGetLineControlsW)        \
	_(mixerGetLineInfoA)            \
	_(mixerGetLineInfoW)            \
	_(mixerGetNumDevs)              \
	_(mixerMessage)                 \
	_(mixerOpen)                    \
	_(mixerSetControlDetails)       \
	_(mmDrvInstall)                 \
	_(mmGetCurrentTask)             \
	_(mmTaskBlock)                  \
	_(mmTaskCreate)                 \
	_(mmTaskSignal)                 \
	_(mmTaskYield)                  \
	_(mmioAdvance)                  \
	_(mmioAscend)                   \
	_(mmioClose)                    \
	_(mmioCreateChunk)              \
	_(mmioDescend)                  \
	_(mmioFlush)                    \
	_(mmioGetInfo)                  \
	_(mmioInstallIOProcA)           \
	_(mmioInstallIOProcW)           \
	_(mmioOpenA)                    \
	_(mmioOpenW)                    \
	_(mmioRead)                     \
	_(mmioRenameA)                  \
	_(mmioRenameW)                  \
	_(mmioSeek)                     \
	_(mmioSendMessage)              \
	_(mmioSetBuffer)                \
	_(mmioSetInfo)                  \
	_(mmioStringToFOURCCA)          \
	_(mmioStringToFOURCCW)          \
	_(mmioWrite)                    \
	_(mmsystemGetVersion)           \
	_(sndPlaySoundA)                \
	_(sndPlaySoundW)                \
	_(timeBeginPeriod)              \
	_(timeEndPeriod)                \
	_(timeGetDevCaps)               \
	_(timeGetSystemTime)            \
	_(timeGetTime)                  \
	_(timeKillEvent)                \
	_(timeSetEvent)                 \
	_(waveInAddBuffer)              \
	_(waveInClose)                  \
	_(waveInGetDevCapsA)            \
	_(waveInGetDevCapsW)            \
	_(waveInGetErrorTextA)          \
	_(waveInGetErrorTextW)          \
	_(waveInGetID)                  \
	_(waveInGetNumDevs)             \
	_(waveInGetPosition)            \
	_(waveInMessage)                \
	_(waveInOpen)                   \
	_(waveInPrepareHeader)          \
	_(waveInReset)                  \
	_(waveInStart)                  \
	_(waveInStop)                   \
	_(waveInUnprepareHeader)        \
	_(waveOutBreakLoop)             \
	_(waveOutClose)                 \
	_(waveOutGetDevCapsA)           \
	_(waveOutGetDevCapsW)           \
	_(waveOutGetErrorTextA)         \
	_(waveOutGetErrorTextW)         \
	_(waveOutGetID)                 \
	_(waveOutGetNumDevs)            \
	_(waveOutGetPitch)              \
	_(waveOutGetPlaybackRate)       \
	_(waveOutGetPosition)           \
	_(waveOutGetVolume)             \
	_(waveOutMessage)               \
	_(waveOutOpen)                  \
	_(waveOutPause)                 \
	_(waveOutPrepareHeader)         \
	_(waveOutReset)                 \
	_(waveOutRestart)               \
	_(waveOutSetPitch)              \
	_(waveOutSetPlaybackRate)       \
	_(waveOutSetVolume)             \
	_(waveOutUnprepareHeader)       \
	_(waveOutWrite)

#define MAP_FUNCTION(name)      \
	{                           \
		#name, &AheadLib_##name \
	}
VOID WINAPI Free()
{
	if (g_OldModule)
	{
		FreeLibrary(g_OldModule);
	}
}

BOOL WINAPI Load()
{
	TCHAR tzPath[MAX_PATH];
	TCHAR tzTemp[MAX_PATH * 2];

	GetSystemDirectory(tzPath, MAX_PATH);

	lstrcat(tzPath, TEXT("\\winmm.dll"));

	g_OldModule = LoadLibrary(tzPath);
	if (g_OldModule == NULL)
	{
		wsprintf(tzTemp, TEXT("can't load %s"), tzPath);
		MessageBox(NULL, tzTemp, TEXT("AheadLib"), MB_ICONSTOP);
	}

	return (g_OldModule != NULL);
}
#include "inlinehook.hpp"
static bool GumFoundCb(const ExportDetails *details,
					   void *user_data)
{
	HMODULE mod = (HMODULE)user_data;
	void *fake = GetProcAddress(mod, details->name);
	void *real = GetProcAddress(g_OldModule, details->name);
	if (real == 0 | fake == 0)
	{
		MessageBoxA(NULL, details->name, "can't find module function", 0);
		std::exit(1);
	}
	Hook((uint8_t *)fake, (uint8_t *)real);
	return true;
}

static void wait_debugger()
{
	TCHAR filePath[MAX_PATH];
	::GetModuleFileName(NULL, filePath, MAX_PATH);

	if (_tcsstr(filePath, _T("dontstarve")) != NULL)
	{
		const auto filename = "Debug.config";
		BOOL enableDebug = ::GetFileAttributesA(filename) != INVALID_FILE_ATTRIBUTES;

		if (enableDebug)
		{
			if (!IsDebuggerPresent())
			{
				STARTUPINFO si;
				ZeroMemory(&si, sizeof(si));
				si.cb = sizeof(si);

				PROCESS_INFORMATION pi;
				ZeroMemory(&pi, sizeof(pi));
				auto cmd = std::format("vsjitdebugger -p {}", GetCurrentProcessId());
				CreateProcessA(NULL, cmd.data(), NULL, NULL, TRUE, CREATE_NEW_CONSOLE, NULL,
							   NULL,
							   &si,
							   &pi);
				CloseHandle(pi.hProcess);
				CloseHandle(pi.hThread);
			}
			auto limit = std::chrono::system_clock::now() + 15s;
			while (!IsDebuggerPresent())
			{
				std::this_thread::yield();
				if (std::chrono::system_clock::now() > limit)
					break;
			}
			auto fp = fopen(filename, "r");
			char buffer[1024] = {};
			if (fread(buffer, sizeof(char), sizeof(buffer) / sizeof(char), fp) > 0)
			{
				_putenv_s("LUA_INIT", buffer);
			}
			fclose(fp);
		}
	}
}
#define DEF_FUNCTION(name)          \
	EXTERN_C void AheadLib_##name() \
	{                               \
		OutputDebugStringA(#name);  \
		DebugBreak();               \
	}
DEF_FUNCTION(Unnamed2)

FUNCTIONS(DEF_FUNCTION)
#include <optional>
#include <filesystem>
std::filesystem::path getUserDoctmentDir()
{
	char path[MAX_PATH];
	SHGetFolderPathA(NULL, CSIDL_MYDOCUMENTS, NULL, 0, path);
	return path;
}

std::filesystem::path getExePath()
{
	char path[MAX_PATH];
	GetModuleFileNameA(NULL, path, 255);
	return std::filesystem::path{path};
}

std::filesystem::path getGameDir()
{
	return getExePath().parent_path().parent_path();
}

bool isClientMod = []()
{
	return !getExePath().filename().string().contains("server");
}();

void DontStarveInjectorStart()
{
	auto dir = getGameDir();
#if 0
	// check version
	auto version_path = dir / "version.txt";
	if (std::filesystem::exists(version_path))
	{
		auto fp = fopen(version_path.string().c_str(), "r");
		uint64_t version = 0;
		fscanf(fp, "%lld", &version);
		fclose(fp);
	}
#endif
	// auto updater
	void updater();
	if (isClientMod)
	{
		updater();
	}
	else
	{
		std::atexit(updater);
	}

	auto mod = LoadLibraryA("injector");
	if (!mod)
	{
		MessageBoxA(NULL, "can't load injector.dll", "Error!", 0);
		std::exit(1);
	}
	auto ptr = (void (*)(bool))GetProcAddress(mod, "Inject");
	ptr(isClientMod);
}
BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, PVOID pvReserved)
{
	static std::atomic_bool loaded = false;
	if (dwReason == DLL_PROCESS_ATTACH)
	{
		if (!loaded && Load())
		{
			loaded = true;
			wait_debugger();
			module_enumerate_exports(hModule, GumFoundCb, hModule);
			void *uname2_ptr = GetProcAddress(g_OldModule, (LPCSTR)2);
			Hook((uint8_t *)&AheadLib_Unnamed2, (uint8_t *)uname2_ptr);
			// check dump
			auto dump_path = getUserDoctmentDir() / "klei" / "DoNotStarveTogether" / "donotstarvetogether_client.dmp";
			if (std::filesystem::exists(dump_path))
			{
				auto msg = L"发现已有的游戏崩溃文件,是否加载模组?\n"
						   L"Found existing game crash file, load module or not?";
				int res = MessageBoxW(NULL,
									  msg,
									  L"MOD:LUAJIT-WARN",
									  MB_YESNO);
				if (res == IDNO)
				{
					return TRUE;
				}
				std::filesystem::remove(dump_path);
			}
			DontStarveInjectorStart();
		}
	}
	else if (dwReason == DLL_PROCESS_DETACH)
	{
		Free();
	}

	return TRUE;
}
