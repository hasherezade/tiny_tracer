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

//---

class PinDataLock
{
public:
    PinDataLock(PIN_LOCK* lock)
        : m_lock(lock)
    {
        PIN_GetLock(m_lock, PIN_GetTid());
    }

    ~PinDataLock()
    {
        PIN_ReleaseLock(m_lock);
    }

private:
    PIN_LOCK* m_lock;
};

