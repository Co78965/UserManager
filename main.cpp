#include <windows.h>
#include <ntsecapi.h>
#include <iostream>
#include <io.h>
#include <fcntl.h>

#include "UsersInfo/UsersInfo.h"
#include "GroupsInfo/GroupsInfo.h"

#pragma comment(lib, "Advapi32.lib")

int main() {
    _setmode(_fileno(stdout), _O_U8TEXT);
    int debug = 1;
    GroupsInfo groups(debug);
    UsersInfo users(&groups, debug);

    if (!(groups.GetGroups() && users.GetUsers())){
        wprintf(L"[ERROR] groups.GetGroups() && users.GetUsers()\n");
        return -1;
    }

    // users.PrintUserInfo(L"lyuga");
    groups.AddGroup({L"NewTestGroup", L"new test group"});
    users.AddUser({L"vanya", L"1", L""});
    users.AddUserPrivilege(L"vanya",L"SeBackupPrivilege");
    users.AddUserPrivilege(L"vanya",L"SeCreatePagefilePrivilege");
    users.PrintUserInfo(L"vanya");

    groups.AddGroupPrivilege(L"NewTestGroup",  L"SeAuditPrivilege");
    groups.AddGroupPrivilege(L"NewTestGroup",  L"SeEnableDelegationPrivilege");
    groups.PrintGroupInfo(L"NewTestGroup");

    users.AddUserToGroup(L"vanya", L"NewTestGroup");
    users.PrintUserInfo(L"vanya");

    users.DeleteUser(L"vanya");
    groups.DeleteGroup(L"NewTestGroup");

    users.PrintUserInfo(L"vanya");
    groups.PrintGroupInfo(L"NewTestGroup");
    return 0;
}
