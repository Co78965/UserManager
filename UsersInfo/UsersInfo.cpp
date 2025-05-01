#include "UsersInfo.h"

bool UsersInfo::DeleteUser(const std::wstring& username) {
    NET_API_STATUS nStatus = NetUserDel(NULL, username.c_str());

    if (nStatus != NERR_Success) {
        std::wcerr <<L"[ERROR] NetUserDel failed! Error code: 0x" << std::hex << nStatus << std::endl;
        return false;
    }

    std::wcout << L"[INFO] User " << username.c_str() << " deleted successfully!" << std::endl;
    return true;
}

USER_INFO_1 UsersInfo::parseData(const std::vector<std::wstring>& data) {
    USER_INFO_1 ui = {0};
    if (data.size() < 3) {
        std::wcerr << L"[ERROR] Not enough parameters in userData\n";
        return USER_INFO_1{};
    }

    // Динамическое выделение памяти
    ui.usri1_name = _wcsdup(data[0].c_str());
    ui.usri1_password = _wcsdup(data[1].c_str());

    ui.usri1_priv = USER_PRIV_USER;
    ui.usri1_home_dir = NULL;
    ui.usri1_comment = NULL;
    ui.usri1_flags = UF_SCRIPT;
    ui.usri1_script_path = NULL;

    return ui;
}

void UsersInfo::printAccountRights(LSA_HANDLE policyHandle, PSID accountSid) {
    PLSA_UNICODE_STRING rights = NULL;
    ULONG rightsCount = 0;
    wprintf(L"\tExplicit privileges:\n");
    NTSTATUS status = LsaEnumerateAccountRights(policyHandle, accountSid, &rights, &rightsCount);
    if (status != 0) {
        wprintf(L"\t\tThe user has no explicit privileges!\n", status);
        return;
    }

    for (ULONG i = 0; i < rightsCount; i++) {
        wprintf(L"\t\t%s (Enabled)\n", rights[i].Buffer);
    }

    LsaFreeMemory(rights);
}

bool UsersInfo::AddUser(const std::vector<std::wstring>& userData) {
    DWORD dwLevel = 1;
    DWORD dwError = 0;

    USER_INFO_1 ui = parseData(userData);
    if (!ui.usri1_name || !ui.usri1_password) {
        return false;
    }

    NET_API_STATUS nStatus = NetUserAdd(NULL, dwLevel, (LPBYTE)&ui, &dwError);

    // Освобождаем память
    free(ui.usri1_name);
    free(ui.usri1_password);

    if (nStatus != NERR_Success) {
        std::wcerr << L"[ERROR] NetUserAdd failed! Error code: 0x" << std::hex << nStatus << std::endl;
        return false;
    }

    std::wcout << L"[INFO] NetUserAdd() is OK!" << std::endl;
    return true;
}

bool UsersInfo::GetUsers() {
    DWORD totalEntries = 0;
    if (NetUserEnum(NULL, 0, FILTER_NORMAL_ACCOUNT, (LPBYTE*)&pBufUsers, MAX_PREFERRED_LENGTH, &entriesReadUsers, &totalEntries, NULL) != NERR_Success) {
        wprintf(L"[ERROR] Failed to retrieve user list.\n");
        return false;
    }
    return true;
}

void UsersInfo::PrintUsersInfo() {
    if (pBufUsers == NULL) {
        wprintf(L"[INFO] User list is empty.\n");
        return;
    }

    LSA_HANDLE policyHandle = NULL;
    LSA_OBJECT_ATTRIBUTES objectAttributes = { 0 };
    objectAttributes.Length = sizeof(objectAttributes);

    if (LsaOpenPolicy(NULL, &objectAttributes, POLICY_LOOKUP_NAMES, &policyHandle) != 0) {
        wprintf(L"[ERROR] Failed to open security policy.\n");
        return;
    }
    wprintf(L"\n----------------------------------------Users info----------------------------------------\n");
    for (DWORD i = 0; i < entriesReadUsers; i++) {
        PrintUserInfo(pBufUsers->usri0_name);    
    }

    LsaClose(policyHandle);
}

void UsersInfo::PrintUserInfo(std::wstring name){
    wprintf(L"\n----------------------------------------%s's info----------------------------------------\n", name.c_str());
    LSA_HANDLE policyHandle = NULL;
    LSA_OBJECT_ATTRIBUTES objectAttributes = { 0 };
    objectAttributes.Length = sizeof(objectAttributes);

    if (LsaOpenPolicy(NULL, &objectAttributes, POLICY_LOOKUP_NAMES, &policyHandle) != 0) {
        wprintf(L"[ERROR] Failed to open security policy.\n");
        return;
    }

    LPUSER_INFO_4 pBuf4 = NULL;
    LPBYTE pBufDetail = NULL;
    NET_API_STATUS nStatus = NetUserGetInfo(NULL, name.c_str(), 4, &pBufDetail);

    if (nStatus == NERR_Success && pBufDetail) {
        pBuf4 = (LPUSER_INFO_4)pBufDetail;
        wprintf(L"User: %s\n", pBuf4->usri4_name);
        wprintf(L"\tPrivilege level: %s\n",
            (pBuf4->usri4_priv == USER_PRIV_GUEST) ? L"Guest" :
            (pBuf4->usri4_priv == USER_PRIV_USER) ? L"User" : L"Administrator");

        wprintf(L"\tFlags: 0x%x\n", pBuf4->usri4_flags);
        wprintf(L"\tPrimary group ID: %d\n", pBuf4->usri4_primary_group_id);

        printAccountRights(policyHandle, pBuf4->usri4_user_sid);
        NetApiBufferFree(pBufDetail);

        // Добавим вывод групп
        DWORD entriesRead = 0, totalEntries = 0;
        LPLOCALGROUP_USERS_INFO_0 pGroups = nullptr;

        nStatus = NetUserGetLocalGroups(
            NULL,
            name.c_str(),
            0,
            LG_INCLUDE_INDIRECT,
            (LPBYTE*)&pGroups,
            MAX_PREFERRED_LENGTH,
            &entriesRead,
            &totalEntries
        );
        wprintf(L"\tGroups:\n");
        if (nStatus == NERR_Success && pGroups != nullptr) {
            for (DWORD i = 0; i < entriesRead; ++i) {
                if (pGroups[i].lgrui0_name)
                    wprintf(L"\t\t%s\n", pGroups[i].lgrui0_name);
                    groups->PrintAccountRights(pGroups[i].lgrui0_name, L"\tInherited privileges:");
            }
            NetApiBufferFree(pGroups);
        } else {
            wprintf(L"\t\tThe user does not belong to groups!", nStatus);
        }
    } else {
        wprintf(L"[ERROR] Failed to retrieve user information for %s (code: %d)\n", name.c_str(), nStatus);
    }

    wprintf(L"\n------------------------------------------------------------------------------------------\n");
    LsaClose(policyHandle);
}

bool UsersInfo::AddUserToGroup(const std::wstring& userName, const std::wstring& groupName) {
    LOCALGROUP_MEMBERS_INFO_3 memberInfo;
    memberInfo.lgrmi3_domainandname = const_cast<LPWSTR>(userName.c_str());

    NET_API_STATUS status = NetLocalGroupAddMembers(NULL, groupName.c_str(), 3, (LPBYTE)&memberInfo, 1);
    
    if (status == NERR_Success) {
        wprintf(L"[INFO] User %s has been added to the group %s\n", userName.c_str(), groupName.c_str());
        return true;
    } else if (status == ERROR_MEMBER_IN_ALIAS) {
        wprintf(L"[INFO] User %s is already a member of the group %s\n", userName.c_str(), groupName.c_str());
    } else {
        wprintf(L"[ERROR] Error adding user %s to the group %s (error code: %d)\n", userName.c_str(), groupName.c_str(), status);
    }
    
    return false;
}

bool UsersInfo::DelUserToGroup(const std::wstring& userName, const std::wstring& groupName) {
    LOCALGROUP_MEMBERS_INFO_3 memberInfo;
    memberInfo.lgrmi3_domainandname = const_cast<LPWSTR>(userName.c_str());

    NET_API_STATUS status = NetLocalGroupDelMembers(NULL, groupName.c_str(), 3, (LPBYTE)&memberInfo, 1);

    if (status == NERR_Success) {
        wprintf(L"[INFO] User %s has been deleted to the group %s\n", userName.c_str(), groupName.c_str());
        return true;
    } else if (status == ERROR_MEMBER_IN_ALIAS) {
        wprintf(L"[INFO] User %s is already deleted from the group %s\n", userName.c_str(), groupName.c_str());
    } else {
        wprintf(L"[ERROR] Error deleted user %s to the group %s (error code: %d)\n", userName.c_str(), groupName.c_str(), status);
    }
    
    return false;
}

bool UsersInfo::AddUserPrivilege(const std::wstring& username, const std::wstring& privilege) {
    // Получение SID
    PSID userSID = nullptr;
    DWORD sidSize = 0, domainSize = 0;
    SID_NAME_USE sidType;

    LookupAccountNameW(NULL, username.c_str(), NULL, &sidSize, NULL, &domainSize, &sidType);
    userSID = (PSID)malloc(sidSize);
    wchar_t* domainName = new wchar_t[domainSize];

    if (!LookupAccountNameW(NULL, username.c_str(), userSID, &sidSize, domainName, &domainSize, &sidType)) {
        std::wcerr << L"[ERROR] LookupAccountNameW failed for " << username << std::endl;
        free(userSID);
        delete[] domainName;
        return false;
    }

    // Открытие LSA Policy
    LSA_HANDLE policyHandle;
    LSA_OBJECT_ATTRIBUTES objAttr = { 0 };

    if (LsaOpenPolicy(NULL, &objAttr, POLICY_ALL_ACCESS, &policyHandle) != 0) {
        std::wcerr << L"[ERROR] LsaOpenPolicy failed\n";
        free(userSID);
        delete[] domainName;
        return false;
    }

    // Преобразование строки в LSA_UNICODE_STRING
    LSA_UNICODE_STRING lsaString;
    lsaString.Buffer = const_cast<LPWSTR>(privilege.c_str());
    lsaString.Length = static_cast<USHORT>(privilege.length() * sizeof(WCHAR));
    lsaString.MaximumLength = lsaString.Length + sizeof(WCHAR);

    // Назначение права
    NTSTATUS status = LsaAddAccountRights(policyHandle, userSID, &lsaString, 1);
    if (status != 0) {
        std::wcerr << L"[ERROR] LsaAddAccountRights failed for " << username
                   << L", NTSTATUS: " << std::hex << status << std::endl;
    } else {
        std::wcout << L"[INFO] Privilege " << privilege << " added successfully to user " << username << std::endl;
    }

    LsaClose(policyHandle);
    free(userSID);
    delete[] domainName;
    return status == 0;
}

bool UsersInfo::RemoveUserPrivilege(const std::wstring& username, const std::wstring& privilege) {
    // Получение SID
    PSID userSID = nullptr;
    DWORD sidSize = 0, domainSize = 0;
    SID_NAME_USE sidType;

    LookupAccountNameW(NULL, username.c_str(), NULL, &sidSize, NULL, &domainSize, &sidType);
    userSID = (PSID)malloc(sidSize);
    wchar_t* domainName = new wchar_t[domainSize];

    if (!LookupAccountNameW(NULL, username.c_str(), userSID, &sidSize, domainName, &domainSize, &sidType)) {
        std::wcerr << L"[ERROR] LookupAccountNameW failed for " << username << std::endl;
        free(userSID);
        delete[] domainName;
        return false;
    }

    // Открытие LSA Policy
    LSA_HANDLE policyHandle;
    LSA_OBJECT_ATTRIBUTES objAttr = { 0 };

    if (LsaOpenPolicy(NULL, &objAttr, POLICY_ALL_ACCESS, &policyHandle) != 0) {
        std::wcerr << L"[ERROR] LsaOpenPolicy failed\n";
        free(userSID);
        delete[] domainName;
        return false;
    }

    // Преобразование строки в LSA_UNICODE_STRING
    LSA_UNICODE_STRING lsaString;
    lsaString.Buffer = const_cast<LPWSTR>(privilege.c_str());
    lsaString.Length = static_cast<USHORT>(privilege.length() * sizeof(WCHAR));
    lsaString.MaximumLength = lsaString.Length + sizeof(WCHAR);

    // Удаление права
    NTSTATUS status = LsaRemoveAccountRights(policyHandle, userSID, FALSE, &lsaString, 1);
    if (status != 0) {
        std::wcerr << L"[ERROR] LsaRemoveAccountRights failed for " << username
                   << L", NTSTATUS: " << std::hex << status << std::endl;
    } else {
        std::wcout << L"[INFO] Privilege " << privilege << " removed successfully from user " << username << std::endl;
    }

    LsaClose(policyHandle);
    free(userSID);
    delete[] domainName;
    return status == 0;
}


void UsersInfo::debug(std::wstring text, int type){
    if(!usersDebug){
        return;
    }
    std::wstring line = L"";
    switch(type){
        case ERROR:
        line = L"[ERROR]";
        break;
        case INFO:
        line = L"[INFO]";
        break;
    }
    wprintf(L"%s %s\n", line.c_str(), text.c_str());
}