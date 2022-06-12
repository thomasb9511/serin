// serin

#include <iostream>
#include <windows.h>

#include "serin.h"

namespace serin
{
    void SetStdinEcho(bool enable)
    {
        const auto    hStdin = GetStdHandle(STD_INPUT_HANDLE);
        unsigned long mode;
        GetConsoleMode(hStdin, &mode);

        if (enable)
            mode |= ENABLE_ECHO_INPUT;
        else
            mode &= ~ENABLE_ECHO_INPUT;

        SetConsoleMode(hStdin, mode);
    }
} // namespace serin
