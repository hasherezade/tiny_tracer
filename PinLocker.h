#pragma once

#include "pin.H"

/*!
*  A locker class.
*/
class PinLocker
{
public:
    PinLocker()
    {
        PIN_LockClient();
    }

    ~PinLocker()
    {
        PIN_UnlockClient();
    }
};
