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
	VOID CpuidCheck(CONTEXT* ctxt);
};
