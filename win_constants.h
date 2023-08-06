#pragma once

//* ==================================================================== */
// Windows Constants. Not always defined in standard Headers
/* ===================================================================== */

// _PROCESSINFOCLASS
#define PROCESSDEBUGPORT			0x7
#define PROCESSDEBUGFLAGS			0x1f
#define PROCESSDEBUGOBJECTHANDLE 	0x1e

// _SYSTEM_INFORMATION_CLASS
#define SYSTEMKERNELDEBUGGERINFORMATION		0x23

// _OBJECT_INFORMATION_CLASS
#define OBJECTTYPESINFORMATION		0x3

// RaiseException constants
#define DBG_CONTROL_C				0x40010005
#define DBG_RIPEVENT				0x40010007
