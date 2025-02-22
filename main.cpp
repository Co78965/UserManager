#include "UserInfo.h"
#include <fcntl.h>
#include <io.h>

int main() {
    _setmode(_fileno(stdout), _O_U8TEXT);
    UsersInfo u;

    std::vector<std::wstring> userData = {L"Name",L"Name",L"user",L"add from bsit_1"};

    if(u.AddUser(userData)){
        std::cout << "Success!" << std::endl;
    }
    
    if (u.GetUsers() && u.GetGroups()) {
        u.PrintUserInfo();
    }

    if(u.DeleteUser(L"Name")){
        std::cout << "Success!" << std::endl;
    }

    if (u.GetUsers() && u.GetGroups()) {
        u.PrintUserInfo();
    }

    return 0;
}