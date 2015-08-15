#include "StdAfx.h"
#include "ModInfo.h"
#include "imageHelper.h"

#define _DUMMY_HANDLE		((HANDLE) this)
#define RET_BUF_SIZE		(8*1024)


ModInfo::ModInfo(void) {

}

static void hexdump(void* pbuf, uint32_t length) {
  uint8_t* pBuf = (uint8_t*)pbuf;
  uint32_t i;

  for (i = 0; i != length; i++) {
    fprintf(stdout, "%02x ", pBuf[i]);
    if ((i + 1) % 16 == 0)
      fprintf(stdout, "\n");
  }
}

void* ModInfo::_findRuntimeFunction(unsigned long long address) {
  MODULE_INFO_ENTRY* modInfo;
  void* res;

  modInfo = _findModoleInfoByAddress(address);
  if (modInfo == NULL) {
  fprintf(stdout, "Error: cant find rtf for %p \n", address);
    return NULL;
  }
  res = findRuntimeFunction(address, modInfo->begin, modInfo->pdataPtr, modInfo->pdataSize);
 
  return res;
}

void* ModInfo::_findRuntimeFunction2(void* handle, unsigned long long address) {
  ModInfo* thos;
  void*	res;

  //fprintf(stdout, "_findRuntimeFunction2\n");

  thos = (ModInfo*)handle;
  res =  thos->_findRuntimeFunction(address);

  if (res == NULL) {
    thos->mLastFindRtfError = TRUE;
  }
  return res;
}

void ModInfo::_preparePdata(MODULE_INFO_ENTRY& modinfo) {
  ULONG size;
  PVOID pData;
  pe_ctx_t* peCtx;

  peCtx = (pe_ctx_t*)modinfo.pefileCtx;
  //fprintf(stdout, "_preparePdata map_addr:%p\n", peCtx->map_addr);
  pData = ImageDirectoryEntryToData(peCtx->map_addr, 0, IMAGE_DIRECTORY_ENTRY_EXCEPTION, &size);
  //fprintf(stdout, "mod:%s pData:%p size:%x\n", modinfo.ExeFileName.c_str(), pData, size);
  modinfo.pdataPtr = pData;
  modinfo.pdataSize = size;
}

BOOL ModInfo::_readRemoteMemory(
    _In_  HANDLE  hProcess,
    _In_  DWORD64 lpBaseAddress,
    _Out_ PVOID   lpBuffer,
    _In_  DWORD   nSize,
    _Out_ LPDWORD lpNumberOfBytesRead
    ) {
  MODULE_INFO_ENTRY* modInfo;
  pe_ctx_t* pe_ctx;
  unsigned int readSize;
  void* readStart;
  ModInfo* thos;

  thos = (ModInfo*)hProcess;
  //fprintf(stdout, "_readRemoteMemory :%p size:%x\n", lpBaseAddress, nSize);
  modInfo = thos->_findModoleInfoByAddress(lpBaseAddress);
  if (modInfo == NULL) {
    //fprintf(stdout, "STACK_READ: %p Rsp:%p Rsp_End:%p\n", lpBaseAddress, thos->mRegisterContext.Rsp,
    //  thos->mRegisterContext.Rsp + thos->m_curStackSize);
    // Check if the read is target to stack?
    if (lpBaseAddress >= (thos->mRegisterContext.Rsp) &&
        lpBaseAddress < thos->mRegisterContext.Rsp + thos->m_curStackSize) {
      readStart = (void*)(lpBaseAddress - (thos->mRegisterContext.Rsp) + (ULONG64)thos->m_curStack);
      readSize = min(thos->mRegisterContext.Rsp + thos->m_curStackSize - lpBaseAddress, nSize);
      //if (nSize != readSize)
      //	;
      //fprintf(stdout, "=== clipped\n");
#if DEBUG
      fprintf(stdout, "--- STACK_READ_2: %p len :%x readStart:%p readSize:%x Rsp:%x offset:%x\n",
              lpBaseAddress, nSize, readStart, readSize, thos->mRegisterContext.Rsp,
              lpBaseAddress - (thos->mRegisterContext.Rsp));

      hexdump(readStart, readSize);
      fprintf(stdout, "----\n");
#endif
      ::memcpy(lpBuffer, readStart, readSize);
      *lpNumberOfBytesRead = readSize;
      return TRUE;
    }
    //fprintf(stdout, "==== failed read 1:%p size:%x\n", lpBaseAddress, nSize);
    return FALSE;
  }
  // target to PE
  pe_ctx = (pe_ctx_t*)modInfo->pefileCtx;
  readStart = (char*)pe_ctx->map_addr + (lpBaseAddress - modInfo->begin);
  readSize = min(lpBaseAddress - modInfo->end, nSize);
  ::memcpy(lpBuffer, readStart, readSize);
  *lpNumberOfBytesRead = readSize;
#if DEBUG
  fprintf(stdout, "---- READ PE %s off:%llx map:%p readStart:%p readSize:%x\n", modInfo->ExeFileName.c_str(), lpBaseAddress - modInfo->begin, pe_ctx->map_addr, readStart, readSize);
  hexdump(readStart, readSize);
  fprintf(stdout, "----\n");
#endif
  return TRUE;
}

ModInfo::ModInfo(boost::python::list& py_list) {
  BOOL res;
  m_curStack = NULL;
  res = 1;

  res = ::SymInitialize(_DUMMY_HANDLE, NULL, 0);
  //fprintf(stdout, "SymInitialize: %x\n", res);
  if (res) {
    res = ::SymRegisterCallback64(_DUMMY_HANDLE, ModInfo::MySymbolCallback, (ULONG64)this);
    //fprintf(stdout, "SymRegisterCallback64 %x\n", res);
    ::SymSetOptions(SYMOPT_DEBUG);
  }


  for (int i = 0; i < len(py_list); ++i) {
    boost::python::dict dd = boost::python::extract<boost::python::dict>(py_list[i]);
    boost::python::extract<unsigned long long int> extracted_base(dd["base"]);
    boost::python::extract<unsigned long long int> extracted_length(dd["length"]);
    boost::python::extract<std::string> extracted_name(dd["name"]);
    std::string exeFileName;
    MODULE_INFO_ENTRY modInfo;
    pe_ctx_t* pe_ctx;
    pe_err_e pe_err;
    bool has_exeFileName = false;
    ULONG64 loadedBase;

    modInfo.pdataPtr = NULL;
    if (!extracted_base.check() || !extracted_length.check() || !extracted_name.check()) {
      continue;
    }
    modInfo.begin = extracted_base;
    modInfo.end = extracted_base + extracted_length;
    modInfo.name = extracted_name;

    has_exeFileName = dd.has_key("exeFileName");
    if (has_exeFileName) {
      boost::python::extract<std::string> extracted_exeFileName(dd["exeFileName"]);
      if (!extracted_exeFileName.check()) {
        continue;
      }
      //fprintf(stdout, "%s loaded base: %p modInfo.begin:%llx end:%llx\n", modInfo.ExeFileName.c_str(), modInfo.pSymLoadedImage, modInfo.begin, modInfo.end);

      modInfo.ExeFileName = extracted_exeFileName;
#if 1
      // Load PE file with libpe
      pe_ctx = new pe_ctx_t();
      pe_err = pe_load_file(pe_ctx, modInfo.ExeFileName.c_str());
      if (pe_err == 0) {
        modInfo.pefileCtx = pe_ctx;
        pe_parse(pe_ctx);
        //fprintf(stdout, "---\n");
        //hexdump((void*)pe_ctx->map_addr, 0x64);
        //_preparePdata(modInfo);
        //fprintf(stdout, "loading modfile:%s ctx:%x result:%x pdata:%p size:%x\n",
        //	modInfo.ExeFileName.c_str(), pe_ctx, pe_err,
        //	modInfo.pdataPtr,
        //	modInfo.pdataSize);
      }
      // Load PE file (symbol module) with dbghelp
      loadedBase = ::SymLoadModuleEx(_DUMMY_HANDLE, NULL, modInfo.ExeFileName.c_str(), NULL,
                                     modInfo.begin, 0, NULL, 0);
      modInfo.pSymLoadedImage = (void*)loadedBase;

      if (loadedBase != NULL) {
        _preparePdata(modInfo);
        fprintf(stdout, "Name:%s pData:%p pDataSize:%x\n", modInfo.ExeFileName.c_str(), modInfo.pdataPtr, modInfo.pdataSize);
      }
      if (loadedBase == 0) {
        fprintf(stdout, "Error: %s cant be loaded\n", modInfo.ExeFileName.c_str());
      }
#endif
    }
    {
      // std::cout << "exeFileName : " << modInfo.ExeFileName << std::endl;
      m_ModList.push_back(modInfo);
    }

  }
}

MODULE_INFO_ENTRY* ModInfo::_findModoleInfoByAddress(unsigned long long address) {
  for (auto i = m_ModList.begin(); i != m_ModList.end(); i++){
    MODULE_INFO_ENTRY& modInfo = *i;
    if (address >= modInfo.begin && address < modInfo.end) {
      return &modInfo;
    }
  }
  return NULL;
}

unsigned long long ModInfo::_findModoleInfoByAddress2(HANDLE hProcess, unsigned long long address) {
  MODULE_INFO_ENTRY* modInfo;
  ModInfo* thos;

  thos = (ModInfo*)hProcess;
  modInfo = thos->_findModoleInfoByAddress(address);
  if (modInfo == NULL) {
    return NULL;
  }
  return modInfo->begin;
}

int ModInfo::test001(void) {
  ULONG64 offset;
  SYMBOL_INFO* symbol;
  ;
  char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
  MODULE_INFO_ENTRY* mod = _findModoleInfoByAddress(0x12000);
  int res;

  if (mod == NULL) {
    fprintf(stdout, "modInfo == NULL\n");
    return -1;
  }
  fprintf(stdout, "loading %s\n", mod->ExeFileName.c_str());
  DWORD64 ModBase = ::SymLoadModuleEx(this, NULL, mod->ExeFileName.c_str(), NULL,
                                      0x12000, 0, NULL, 0);

  memset(&symbol, 0, sizeof(symbol));
  symbol = (SYMBOL_INFO*)buffer;
  symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
  symbol->MaxNameLen = MAX_SYM_NAME;

  if (ModBase == 0) {
    DWORD err = ::GetLastError();
    fprintf(stdout, "LastError:%x\n", err);
  }
  offset = 0;
  fprintf(stdout, "ModBase:%x\n", ModBase);

  res = ::SymFromAddr(this, 0x12000, &offset, symbol);
  fprintf(stdout, "SymFromAddr: %x %s\n", res, symbol->Name);
}

std::string ModInfo::DoStackWalk(int inital) {
  int                res;
  int                res2;
  int                res3;
  int                imageType;
  STACKFRAME64       frame;
  ULONG64            offset;
  SYMBOL_INFO*       symbol;
  static char        buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
  static char        _retBuf[RET_BUF_SIZE];
  char*              retbuf_wr;
  char*              retbuf_end;
  char*              stra;
  CONTEXT            regCtx;


  if (inital == 0) {
    retbuf_wr = &_retBuf[0];
    memset(retbuf_wr, 0, RET_BUF_SIZE);
    retbuf_end = &_retBuf[RET_BUF_SIZE];
    memset(&frame, 0, sizeof(frame));
    imageType = IMAGE_FILE_MACHINE_AMD64;
    frame.AddrPC.Offset = mRegisterContext.Rip;
    frame.AddrPC.Mode = AddrModeFlat;
    frame.AddrFrame.Offset = mRegisterContext.Rbp;
    frame.AddrFrame.Mode = AddrModeFlat;
    frame.AddrStack.Offset = mRegisterContext.Rsp;
    frame.AddrStack.Mode = AddrModeFlat;
    mLastFindRtfError = 0;
  }
#if DEBUG
  fprintf(stdout, "stack init PC:%x frame:%x stack:%x FuncTableEntry:%x\n", frame.AddrPC.Offset, frame.AddrFrame.Offset, frame.AddrStack.Offset, frame.FuncTableEntry);
#endif

  memcpy(&regCtx, &mRegisterContext, sizeof(mRegisterContext));
  do {
    res = ::StackWalk64(imageType,
                        _DUMMY_HANDLE,
                        _DUMMY_HANDLE,
                        &frame,
                        &regCtx,
                        ModInfo::_readRemoteMemory,
                        ModInfo::_findRuntimeFunction2,
                        ModInfo::_findModoleInfoByAddress2,
                        NULL);


    memset(&buffer[0], 0, sizeof(buffer));
    symbol = (SYMBOL_INFO*)buffer;
    symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    symbol->MaxNameLen = MAX_SYM_NAME;


    offset = 0;
    res2 = ::SymFromAddr(this, frame.AddrReturn.Offset, &offset, symbol);

    if (res2) {
      stra = &symbol->Name[0];
    } else {
      offset = 0;
      stra = NULL;
    }

    res3 = _snprintf(retbuf_wr, retbuf_end - retbuf_wr,
                     "Pc:%llx AddrReturn:%llx (%s+%x) Frame:%llx (SP+%llx)\n",
                     frame.AddrPC.Offset,
                     (frame.AddrReturn.Offset),
                     //&symbol->Name ,
                     stra,
                     offset,
                     frame.AddrFrame.Offset,\
                         frame.AddrFrame.Offset - mRegisterContext.Rsp);
    retbuf_wr += res3;

    if (mLastFindRtfError != 0) {
      break;
    }

  } while (res == 1);

  return &_retBuf[0];
}

BOOL CALLBACK ModInfo::MySymbolCallback(
    _In_     HANDLE  hProcess,
    _In_     ULONG   ActionCode,
    _In_opt_ ULONG64 CallbackData,
    _In_opt_ ULONG64 UserContext
    ) {
  ModInfo* modInfo = (ModInfo*)hProcess;
  int res;

  fprintf(stdout, "Action:%x\n", ActionCode);
  switch (ActionCode) {
    case CBA_READ_MEMORY:
      {
        PIMAGEHLP_CBA_READ_MEMORY readMempory = (PIMAGEHLP_CBA_READ_MEMORY)CallbackData;
        fprintf(stdout, "CBA_READ_MEMORY %x %x\n", readMempory->addr, readMempory->bytes);
        res = _readRemoteMemory(hProcess, readMempory->addr, readMempory->buf, readMempory->bytes, readMempory->bytesread);
        if (res != 0) {
          fprintf(stdout, "Can read memory for %x\n", readMempory->addr);
        }
        break;
      }
    case CBA_DEBUG_INFO:
      {
        fprintf(stdout, "CBA_DEBUG_INFO %s\n", (char*)CallbackData);
        break;
      }
    case CBA_DEFERRED_SYMBOL_LOAD_START:
      {
        PIMAGEHLP_DEFERRED_SYMBOL_LOAD64 load64 = (PIMAGEHLP_DEFERRED_SYMBOL_LOAD64)CallbackData;
        fprintf(stdout, "CBA_DEFERRED_SYMBOL_LOAD_START %s\n", (char*)load64->FileName);
        break;
      }
  }



  return 0;
}

boost::python::tuple ModInfo::GetModuleName(unsigned long long address) {
  MODULE_INFO_ENTRY* modInfo;

  modInfo = _findModoleInfoByAddress(address);
  if (modInfo != NULL) {
    return boost::python::make_tuple(modInfo->name, address - modInfo->begin, address);
  }
  return boost::python::make_tuple(NULL, NULL, NULL);
}

#define _UPDATE_CTX_REG(x, y) mRegisterContext.x = contextX64->y

int ModInfo::SetRegisterContext(boost::python::object buffer) {
  PyObject* pyo = buffer.ptr();
  char* buf;
  Py_ssize_t len;
  int res;
  EFI_SYSTEM_CONTEXT_X64* contextX64 = NULL;

  if (!PyString_Check(pyo)) {
    return 2;
  }
  res = PyString_AsStringAndSize(pyo, &buf, &len);
  if (res != 0) {
    buf = NULL;
    len = 0;
    return 1;
  }
  memset(&mRegisterContext, 0, sizeof(mRegisterContext));
  mRegisterContext.ContextFlags = CONTEXT_FULL;
  contextX64 = (EFI_SYSTEM_CONTEXT_X64*)buf;
  _UPDATE_CTX_REG(Dr0, Dr0);
  _UPDATE_CTX_REG(Dr1, Dr1);
  _UPDATE_CTX_REG(Dr2, Dr2);
  _UPDATE_CTX_REG(Dr3, Dr3);
  _UPDATE_CTX_REG(Dr6, Dr6);
  _UPDATE_CTX_REG(Dr7, Dr7);
  _UPDATE_CTX_REG(SegCs, Cs);
  _UPDATE_CTX_REG(SegDs, Ds);
  _UPDATE_CTX_REG(SegEs, Es);
  _UPDATE_CTX_REG(SegFs, Fs);
  _UPDATE_CTX_REG(SegGs, Gs);
  _UPDATE_CTX_REG(SegSs, Ss);

  _UPDATE_CTX_REG(EFlags, Rflags);
  _UPDATE_CTX_REG(Rax, Rax);
  _UPDATE_CTX_REG(Rcx, Rcx);
  _UPDATE_CTX_REG(Rdx, Rdx);
  _UPDATE_CTX_REG(Rbx, Rbx);
  _UPDATE_CTX_REG(Rsp, Rsp);
  _UPDATE_CTX_REG(Rbp, Rbp);
  _UPDATE_CTX_REG(Rsi, Rsi);
  _UPDATE_CTX_REG(Rdi, Rdi);
  _UPDATE_CTX_REG(R8, R8);
  _UPDATE_CTX_REG(R9, R9);
  _UPDATE_CTX_REG(R10, R10);
  _UPDATE_CTX_REG(R11, R11);
  _UPDATE_CTX_REG(R12, R12);
  _UPDATE_CTX_REG(R13, R13);
  _UPDATE_CTX_REG(R14, R14);
  _UPDATE_CTX_REG(R15, R15);
  _UPDATE_CTX_REG(Rip, Rip);

  return 0;
}

int ModInfo::SetStackRaw(boost::python::object buffer) {
  PyObject* pyo = buffer.ptr();
  char* buf;
  Py_ssize_t len;
  int res;
  void* newRawStack;

  if (!PyString_Check(pyo)) {
    return 2;
  }
  res = PyString_AsStringAndSize(pyo, &buf, &len);
  if (res != 0) {
    buf = NULL;
    len = 0;
    return 1;
  }
  if (m_curStack != NULL)
    delete m_curStack;
  newRawStack = new(unsigned char[len]);
  memcpy(newRawStack, buf, len);
  m_curStack = newRawStack;
  m_curStackSize = len;
  return 0;
}

ModInfo::~ModInfo(void) {
  // fprintf(stdout, "~ModInfo\n");
  ::SymCleanup(this);
}
