#include "UsersInfo.h"

bool UsersInfo::DeleteUser(const std::wstring& username) {
    NET_API_STATUS nStatus = NetUserDel(NULL, username.c_str());

    if (nStatus != NERR_Success) {
        debug(L"NetUserDel failed for user " + username + L". Error code: 0x" + std::to_wstring(nStatus), ERROR);
        return false;
    }

    debug(L"User " + username + L" deleted successfully!", INFO);
    return true;
}

USER_INFO_1 UsersInfo::parseData(const std::vector<std::wstring>& data) {
    USER_INFO_1 ui = {0};
    if (data.size() < 2) {
        debug(L"Not enough parameters in userData. Required: 2, got: " + std::to_wstring(data.size()), ERROR);
        return USER_INFO_1{};
    }

    ui.usri1_name = _wcsdup(data[0].c_str());
    ui.usri1_password = _wcsdup(data[1].c_str());
    ui.usri1_priv = USER_PRIV_USER;
    ui.usri1_home_dir = NULL;
    ui.usri1_comment = NULL;
    ui.usri1_flags = UF_SCRIPT;
    ui.usri1_script_path = NULL;

    return ui;
}

LSA_HANDLE UsersInfo::getPolicy(){
    LSA_HANDLE policyHandle = NULL;
    LSA_OBJECT_ATTRIBUTES objectAttributes = { 0 };
    objectAttributes.Length = sizeof(objectAttributes);

    NTSTATUS status = LsaOpenPolicy(NULL, &objectAttributes, POLICY_ALL_ACCESS, &policyHandle);
    if (status != 0) {
        debug(L"Failed to open security policy. NTSTATUS: " + std::to_wstring(status), ERROR);
        return NULL;
    }
    return policyHandle;
}

PSID UsersInfo::getPSID(std::wstring username){
    PSID userSID = nullptr;
    DWORD sidSize = 0, domainSize = 0;
    SID_NAME_USE sidType;

    LookupAccountNameW(NULL, username.c_str(), NULL, &sidSize, NULL, &domainSize, &sidType);
    userSID = (PSID)malloc(sidSize);
    wchar_t* domainName = new wchar_t[domainSize];

    if (!LookupAccountNameW(NULL, username.c_str(), userSID, &sidSize, domainName, &domainSize, &sidType)) {
        debug(L"LookupAccountNameW failed for " + username + L". Error code: " + std::to_wstring(GetLastError()), ERROR);
        free(userSID);
        delete[] domainName;
        return false;
    }
    return userSID;
}

void UsersInfo::PrintAccountRights(std::wstring name) {
    LSA_HANDLE policyHandle = getPolicy();
    PSID accountSid = getPSID(name);

    PLSA_UNICODE_STRING rights = NULL;
    ULONG rightsCount = 0;
    wprintf(L"\tExplicit privileges:\n");
    
    NTSTATUS status = LsaEnumerateAccountRights(policyHandle, accountSid, &rights, &rightsCount);
    if (status != 0) {
        wprintf(L"\t\tThe user has no explicit privileges!\n");
        return;
    }

    for (ULONG i = 0; i < rightsCount; i++) {
        wprintf(L"\t\t%s (Enabled)\n", rights[i].Buffer);
    }

    LsaFreeMemory(rights);
}

//userData[0] - name, userData[1] - password 
bool UsersInfo::AddUser(const std::vector<std::wstring>& userData) {
    DWORD dwLevel = 1;
    DWORD dwError = 0;

    USER_INFO_1 ui = parseData(userData);
    if (!ui.usri1_name || !ui.usri1_password) {
        debug(L"Failed to parse user data", ERROR);
        return false;
    }

    NET_API_STATUS nStatus = NetUserAdd(NULL, dwLevel, (LPBYTE)&ui, &dwError);

    free(ui.usri1_name);
    free(ui.usri1_password);

    if (nStatus != NERR_Success) {
        debug(L"NetUserAdd failed. Error code: 0x" + std::to_wstring(nStatus), ERROR);
        return false;
    }

    debug(L"User added successfully", INFO);
    return true;
}

bool UsersInfo::GetUsers() {
    DWORD totalEntries = 0;
    NET_API_STATUS status = NetUserEnum(NULL, 0, FILTER_NORMAL_ACCOUNT, (LPBYTE*)&pBufUsers, 
                                      MAX_PREFERRED_LENGTH, &entriesReadUsers, &totalEntries, NULL);
    if (status != NERR_Success) {
        debug(L"Failed to retrieve user list. Error code: " + std::to_wstring(status), ERROR);
        return false;
    }
    return true;
}

void UsersInfo::PrintUsersInfo() {
    if (pBufUsers == NULL) {
        debug(L"User list is empty", INFO);
        return;
    }

    LSA_HANDLE policyHandle = getPolicy();

    wprintf(L"----------------------------------------Users info----------------------------------------\n");
    for (DWORD i = 0; i < entriesReadUsers; i++) {
        PrintUserInfo(pBufUsers[i].usri0_name);    
    }

    LsaClose(policyHandle);
}

void UsersInfo::PrintUserInfo(std::wstring name) {
    wprintf(L"----------------------------------------%s's info----------------------------------------\n", name.c_str());
    
    LSA_HANDLE policyHandle = getPolicy();

    LPUSER_INFO_4 pBuf4 = NULL;
    LPBYTE pBufDetail = NULL;
    NET_API_STATUS nStatus = NetUserGetInfo(NULL, name.c_str(), 4, &pBufDetail);

    if (nStatus == NERR_Success && pBufDetail) {
        pBuf4 = (LPUSER_INFO_4)pBufDetail;
        wprintf(L"User: %s\n", pBuf4->usri4_name);
        wprintf(L"\tPrivilege level: %s\n",
            (pBuf4->usri4_priv == USER_PRIV_GUEST) ? L"Guest" :
            (pBuf4->usri4_priv == USER_PRIV_USER) ? L"User" : L"Administrator");
        
        wprintf(L"\tPrimary group ID: %d\n", pBuf4->usri4_primary_group_id);
        
        PrintAccountRights(pBuf4->usri4_name);
        NetApiBufferFree(pBufDetail);

        // Вывод групп пользователя
        LPLOCALGROUP_USERS_INFO_0 pGroups = nullptr;
        DWORD entriesRead = 0, totalEntries = 0;

        nStatus = NetUserGetLocalGroups(
            NULL, name.c_str(), 0, LG_INCLUDE_INDIRECT,
            (LPBYTE*)&pGroups, MAX_PREFERRED_LENGTH,
            &entriesRead, &totalEntries
        );

        wprintf(L"\tGroups:\n");
        if (nStatus == NERR_Success && pGroups != nullptr) {
            for (DWORD i = 0; i < entriesRead; ++i) {
                if (pGroups[i].lgrui0_name) {
                    wprintf(L"\t\t%s\n", pGroups[i].lgrui0_name);
                    groups->PrintAccountRights(pGroups[i].lgrui0_name, L"\tInherited privileges:");
                }
            }
            NetApiBufferFree(pGroups);
        } else {
            wprintf(L"\t\tThe user does not belong to groups!\n");
        }
    } else {
        wprintf(L"User %s doesn't excist!\n", name.c_str());
        debug(L"Failed to retrieve user information for " + name + L". Error code: " + std::to_wstring(nStatus), ERROR);
    }

    wprintf(L"------------------------------------------------------------------------------------------\n");
    LsaClose(policyHandle);
}

bool UsersInfo::AddUserToGroup(const std::wstring& userName, const std::wstring& groupName) {
    LOCALGROUP_MEMBERS_INFO_3 memberInfo;
    memberInfo.lgrmi3_domainandname = const_cast<LPWSTR>(userName.c_str());

    NET_API_STATUS status = NetLocalGroupAddMembers(NULL, groupName.c_str(), 3, (LPBYTE)&memberInfo, 1);
    
    if (status == NERR_Success) {
        debug(L"User " + userName + L" has been added to the group " + groupName, INFO);
        return true;
    } else if (status == ERROR_MEMBER_IN_ALIAS) {
        debug(L"User " + userName + L" is already a member of the group " + groupName, INFO);
    } else {
        debug(L"Error adding user " + userName + L" to the group " + groupName + L". Error code: " + std::to_wstring(status), ERROR);
    }
    
    return false;
}

bool UsersInfo::DelUserToGroup(const std::wstring& userName, const std::wstring& groupName) {
    LOCALGROUP_MEMBERS_INFO_3 memberInfo;
    memberInfo.lgrmi3_domainandname = const_cast<LPWSTR>(userName.c_str());

    NET_API_STATUS status = NetLocalGroupDelMembers(NULL, groupName.c_str(), 3, (LPBYTE)&memberInfo, 1);

    if (status == NERR_Success) {
        debug(L"User " + userName + L" has been removed from the group " + groupName, INFO);
        return true;
    } else if (status == ERROR_MEMBER_IN_ALIAS) {
        debug(L"User " + userName + L" is already not a member of the group " + groupName, INFO);
    } else {
        debug(L"Error removing user " + userName + L" from the group " + groupName + L". Error code: " + std::to_wstring(status), ERROR);
    }
    
    return false;
}

bool UsersInfo::AddUserPrivilege(const std::wstring& username, const std::wstring& privilege) {
    PSID userSID = getPSID(username);
    if (!userSID) {
        debug(username + L"'s sid is empty", ERROR);
        return false;
    }
    LSA_HANDLE policyHandle = getPolicy();
    if (!policyHandle) {
        free(userSID);
        return false;
    }

    LSA_UNICODE_STRING lsaString;
    lsaString.Buffer = const_cast<LPWSTR>(privilege.c_str());
    lsaString.Length = static_cast<USHORT>(privilege.length() * sizeof(WCHAR));
    lsaString.MaximumLength = lsaString.Length + sizeof(WCHAR);

    NTSTATUS status = LsaAddAccountRights(policyHandle, userSID, &lsaString, 1);
    if (status != 0) {
        debug(L"LsaAddAccountRights failed for " + username + L". NTSTATUS: " + std::to_wstring(status), ERROR);
    } else {
        debug(L"Privilege " + privilege + L" added successfully to user " + username, INFO);
    }

    LsaClose(policyHandle);
    free(userSID);
    return status == 0;
}

bool UsersInfo::RemoveUserPrivilege(const std::wstring& username, const std::wstring& privilege) {
    PSID userSID = getPSID(username);

    LSA_HANDLE policyHandle = getPolicy();

    LSA_UNICODE_STRING lsaString;
    lsaString.Buffer = const_cast<LPWSTR>(privilege.c_str());
    lsaString.Length = static_cast<USHORT>(privilege.length() * sizeof(WCHAR));
    lsaString.MaximumLength = lsaString.Length + sizeof(WCHAR);

    NTSTATUS status = LsaRemoveAccountRights(policyHandle, userSID, FALSE, &lsaString, 1);
    if (status != 0) {
        debug(L"LsaRemoveAccountRights failed for " + username + L". NTSTATUS: " + std::to_wstring(status), ERROR);
    } else {
        debug(L"Privilege " + privilege + L" removed successfully from user " + username, INFO);
    }

    LsaClose(policyHandle);
    free(userSID);
    return status == 0;
}

void UsersInfo::DebugOnOff(){
    debug(L"disabling debug", INFO);
    usersDebug = !usersDebug;
    debug(L"enabling debug", INFO);
}

void UsersInfo::debug(std::wstring text, int type){
    if(!usersDebug){
        return;
    }
    std::wstring line = L"";
    WORD color = 0;
    switch(type){
        case ERROR:
        line = L"[ERROR]";
        color = 12;
        break;
        case INFO:
        color = 8;
        line = L"[INFO]";
        break;
    }
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
    wprintf(L"%s %s\n", line.c_str(), text.c_str());
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 15);
}