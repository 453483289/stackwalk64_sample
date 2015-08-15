#pragma once
#include "stdafx.h"

#include <boost/python.hpp>
#include <boost/python/module.hpp>
#include <boost/python/def.hpp>
#include <vector>
#include <string>
#include <Windows.h>
#define _DONT_USE_LIBPE_DECLAR_
#include "pe.h"

#define BAD_PROCESS_HANDLE		(PVOID)(0x11223344)

///
/// FXSAVE_STATE.
/// FP / MMX / XMM registers (see fxrstor instruction definition).
///
typedef struct {
  UINT16  Fcw;
  UINT16  Fsw;
  UINT16  Ftw;
  UINT16  Opcode;
  UINT64  Rip;
  UINT64  DataOffset;
  UINT8   Reserved1[8];
  UINT8   St0Mm0[10], Reserved2[6];
  UINT8   St1Mm1[10], Reserved3[6];
  UINT8   St2Mm2[10], Reserved4[6];
  UINT8   St3Mm3[10], Reserved5[6];
  UINT8   St4Mm4[10], Reserved6[6];
  UINT8   St5Mm5[10], Reserved7[6];
  UINT8   St6Mm6[10], Reserved8[6];
  UINT8   St7Mm7[10], Reserved9[6];
  UINT8   Xmm0[16];
  UINT8   Xmm1[16];
  UINT8   Xmm2[16];
  UINT8   Xmm3[16];
  UINT8   Xmm4[16];
  UINT8   Xmm5[16];
  UINT8   Xmm6[16];
  UINT8   Xmm7[16];
  //
  // NOTE: UEFI 2.0 spec definition as follows. 
  //
  UINT8   Reserved11[14 * 16];
} EFI_FX_SAVE_STATE_X64;

///
///  x64 processor context definition.
///
typedef struct {
  UINT64                ExceptionData;
  EFI_FX_SAVE_STATE_X64 FxSaveState;
  UINT64                Dr0;
  UINT64                Dr1;
  UINT64                Dr2;
  UINT64                Dr3;
  UINT64                Dr6;
  UINT64                Dr7;
  UINT64                Cr0;
  UINT64                Cr1;  /* Reserved */
  UINT64                Cr2;
  UINT64                Cr3;
  UINT64                Cr4;
  UINT64                Cr8;
  UINT64                Rflags;
  UINT64                Ldtr;
  UINT64                Tr;
  UINT64                Gdtr[2];
  UINT64                Idtr[2];
  UINT64                Rip;
  UINT64                Gs;
  UINT64                Fs;
  UINT64                Es;
  UINT64                Ds;
  UINT64                Cs;
  UINT64                Ss;
  UINT64                Rdi;
  UINT64                Rsi;
  UINT64                Rbp;
  UINT64                Rsp;
  UINT64                Rbx;
  UINT64                Rdx;
  UINT64                Rcx;
  UINT64                Rax;
  UINT64                R8;
  UINT64                R9;
  UINT64                R10;
  UINT64                R11;
  UINT64                R12;
  UINT64                R13;
  UINT64                R14;
  UINT64                R15;
} EFI_SYSTEM_CONTEXT_X64;

typedef struct _MODULE_INFO_ENTRY {
	unsigned long long begin;
	unsigned long long end;
	std::string	name;
	std::string ExeFileName;
	// There are two copy of loaded image
	void	*pLoadedImage;				// libpe used loaded base address
	unsigned long LoadedImageSize;
	void	*pSymLoadedImage;			// dbghelp used loaded base address
	void *pefileCtx; // pointer to libpe pe_ctx
	void *pdataPtr;	// ptr to .pdata section
	unsigned long pdataSize;
} MODULE_INFO_ENTRY;

typedef std::vector<MODULE_INFO_ENTRY> ModuleInfoList;

class ModInfo
{
public:
	ModInfo(void);
	ModInfo(boost::python::list& py_list);	
	boost::python::tuple GetModuleName(unsigned long long address);
	int SetRegisterContext(boost::python::object buffer);
	int SetStackRaw(boost::python::object buffer);
	std::string DoStackWalk(int inital);
	~ModInfo(void);

protected:
	  void *m_curStack;
	  unsigned int m_curStackSize;
      ModuleInfoList m_ModList;
      CONTEXT mRegisterContext;

	  UINT8 mLastFindRtfError;

      MODULE_INFO_ENTRY* _findModoleInfoByAddress(unsigned long long address);
	  static unsigned long long _findModoleInfoByAddress2(HANDLE  hProcess, unsigned long long address);
      void* _findRuntimeFunction(unsigned long long address);
	  static void* _findRuntimeFunction2(void *, unsigned long long address);
      void _preparePdata(MODULE_INFO_ENTRY &modinfo);
      static BOOL _readRemoteMemory(
		  _In_  HANDLE  hProcess,
          _In_  DWORD64 lpBaseAddress,
          _Out_ PVOID   lpBuffer,
          _In_  DWORD   nSize,
          _Out_ LPDWORD lpNumberOfBytesRead
          );
	  static BOOL CALLBACK MySymbolCallback(
		  _In_     HANDLE  hProcess,
		  _In_     ULONG   ActionCode,
		  _In_opt_ ULONG64 CallbackData,
		  _In_opt_ ULONG64 UserContext
		);	  
	  int test001(void);
};

