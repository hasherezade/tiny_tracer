#pragma once

#include "pin.H"

//* ==================================================================== */
// Helpers
/* ===================================================================== */
#define GET_STR_TO_UPPER(c, buf, bufSize)	do { \
			size_t i; \
			for (i = 0; i < bufSize; i++) { \
				(buf)[i] = toupper((c)[i]); \
				if ((c)[i] == '\0') break; \
			} \
} while (0)

//* ==================================================================== */
// Prototypes
/* ===================================================================== */
namespace AntiVm {
	VOID MonitorAntiVmFunctions(IMG Image);
	VOID CpuidCheck(CONTEXT* ctxt, THREADID tid);
	VOID CpuidCheck_after(CONTEXT* ctxt, THREADID tid);

	ADDRINT AlterCpuidValueEax(CONTEXT* ctxt, THREADID tid);
	ADDRINT AlterCpuidValueEbx(CONTEXT* ctxt, THREADID tid);
	ADDRINT AlterCpuidValueEcx(CONTEXT* ctxt, THREADID tid);
	ADDRINT AlterCpuidValueEdx(CONTEXT* ctxt, THREADID tid);
};
