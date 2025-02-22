#include "UserInfo.h"
#include <fcntl.h>
#include <io.h>

int wmain() {
    _setmode(_fileno(stdout), _O_U8TEXT);
    UsersInfo u;

    int mode = -1;

    if (u.GetUsers() && u.GetGroups()) {
        u.PrintGroupInfo();
    }
    return 0;
}