// serin

#include <iostream>
#include <windows.h>

#include "serin.h"

namespace serin
{
    void SetStdinEcho(bool enable) {
        const auto    hStdin = GetStdHandle(STD_INPUT_HANDLE);
        unsigned long mode   = 0;
        GetConsoleMode(hStdin, &mode);

        enable ? mode |= ENABLE_ECHO_INPUT : mode &= ~ENABLE_ECHO_INPUT;

        SetConsoleMode(hStdin, mode);
    }
} // namespace serin
