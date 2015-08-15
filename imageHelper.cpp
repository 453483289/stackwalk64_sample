#include "stdafx.h"

void* findRuntimeFunction(unsigned long long addr, unsigned long long imageBase, void* pData, unsigned int size) {
  unsigned int      min;
  unsigned int      max;
  unsigned int      pos;
  RUNTIME_FUNCTION* rtf;

  //fprintf(stdout, "addr:%p base:%p pData:%p size:%x\n", addr, imageBase, pData, size);

  rtf = (RUNTIME_FUNCTION*)pData;
  for (min = 0, max = size / sizeof(*rtf); min <= max;) {
    pos = (min + max) / 2;
    if (addr < imageBase + rtf[pos].BeginAddress)
      max = pos - 1;
    else if (addr >= imageBase + rtf[pos].EndAddress)
      min = pos + 1;
    else  {
      rtf += pos;
      //while (rtf->UnwindData & 1)  /* follow chained entry */
      {
        //fprintf(stdout, "rtf:%p begin:%p end:%p\n", rtf, rtf[0].BeginAddress, rtf[0].EndAddress);
      }
      return rtf;
    }
  }
  return NULL;

}
