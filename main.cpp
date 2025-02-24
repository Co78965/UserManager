#include <iostream>
#include <vector>
#include <string>
#include <windows.h>
#include <lm.h>
#include <io.h>
#include <fcntl.h>
#include "UsersInfo.h"

#pragma comment(lib, "netapi32.lib")

// Function to add a user to a local group
bool AddUserToGroup(const std::wstring& user, const std::wstring& group) {
    LOCALGROUP_MEMBERS_INFO_3 memberInfo;
    memberInfo.lgrmi3_domainandname = const_cast<LPWSTR>(user.c_str());

    NET_API_STATUS status = NetLocalGroupAddMembers(NULL, group.c_str(), 3, (LPBYTE)&memberInfo, 1);
    
    if (status == NERR_Success) {
        wprintf(L"User %s has been added to the group %s\n", user.c_str(), group.c_str());
        return true;
    } else if (status == ERROR_MEMBER_IN_ALIAS) {
        wprintf(L"User %s is already a member of the group %s\n", user.c_str(), group.c_str());
    } else {
        wprintf(L"Error adding user %s to the group %s (error code: %d)\n", user.c_str(), group.c_str(), status);
    }
    
    return false;
}

bool DelUserToGroup(const std::wstring& user, const std::wstring& group) {
    LOCALGROUP_MEMBERS_INFO_3 memberInfo;
    memberInfo.lgrmi3_domainandname = const_cast<LPWSTR>(user.c_str());

    NET_API_STATUS status = NetLocalGroupDelMembers(NULL, group.c_str(), 3, (LPBYTE)&memberInfo, 1);

    if (status == NERR_Success) {
        wprintf(L"User %s has been deleted to the group %s\n", user.c_str(), group.c_str());
        return true;
    } else if (status == ERROR_MEMBER_IN_ALIAS) {
        wprintf(L"User %s is already deleted from the group %s\n", user.c_str(), group.c_str());
    } else {
        wprintf(L"Error deleted user %s to the group %s (error code: %d)\n", user.c_str(), group.c_str(), status);
    }
    
    return false;
}

int main() {
    // Set Unicode mode (UTF-16) for proper output
    _setmode(_fileno(stdout), _O_U16TEXT);

    std::wstring user = L"TestUser";
    wprintf(L"User: %s\n", user.c_str());

    LPBYTE buffer = nullptr;
    DWORD entries = 0, total_entries = 0;

    // Get local groups
    wprintf(L"Local groups:\n");
    NET_API_STATUS status = NetUserGetLocalGroups(NULL, user.c_str(), 0, LG_INCLUDE_INDIRECT, &buffer, MAX_PREFERRED_LENGTH, &entries, &total_entries);
    if (status == NERR_Success && buffer) {
        LOCALGROUP_USERS_INFO_0* groups = reinterpret_cast<LOCALGROUP_USERS_INFO_0*>(buffer);
        for (DWORD i = 0; i < entries; i++)
            wprintf(L"\t%s\n", groups[i].lgrui0_name);
        NetApiBufferFree(buffer);
    } else {
        wprintf(L"Error retrieving local groups (code: %d)\n", status);
    }

    // Add user to a local group (change group name as needed)
    std::wstring group = L"NewTestGroup"; // Change if needed
    AddUserToGroup(user, group);

    // Get local groups
    wprintf(L"Local groups:\n");
    status = NetUserGetLocalGroups(NULL, user.c_str(), 0, LG_INCLUDE_INDIRECT, &buffer, MAX_PREFERRED_LENGTH, &entries, &total_entries);
    if (status == NERR_Success && buffer) {
        LOCALGROUP_USERS_INFO_0* groups = reinterpret_cast<LOCALGROUP_USERS_INFO_0*>(buffer);
        for (DWORD i = 0; i < entries; i++)
            wprintf(L"\t%s\n", groups[i].lgrui0_name);
        NetApiBufferFree(buffer);
    } else {
        wprintf(L"Error retrieving local groups (code: %d)\n", status);
    }

    DelUserToGroup(user, group);

    wprintf(L"Local groups:\n");
    status = NetUserGetLocalGroups(NULL, user.c_str(), 0, LG_INCLUDE_INDIRECT, &buffer, MAX_PREFERRED_LENGTH, &entries, &total_entries);
    if (status == NERR_Success && buffer) {
        LOCALGROUP_USERS_INFO_0* groups = reinterpret_cast<LOCALGROUP_USERS_INFO_0*>(buffer);
        for (DWORD i = 0; i < entries; i++)
            wprintf(L"\t%s\n", groups[i].lgrui0_name);
        NetApiBufferFree(buffer);
    } else {
        wprintf(L"Error retrieving local groups (code: %d)\n", status);
    }
    return 0;

    // UsersInfo u;

    // u.GetUsers();
    // u.DeleteUser(L"TestUser2");
    // u.DeleteUser(L"TestUser");
}