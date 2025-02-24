#include "GroupsInfo.h"

GROUP_INFO_1 GroupsInfo::parseData(const std::vector<std::wstring>& data) {
    GROUP_INFO_1 gi = {0};
    if (data.empty()) {
        std::cerr << "[ERROR] Not enough parameters in groupData\n";
        return GROUP_INFO_1{};
    }

    // Динамическое выделение памяти
    gi.grpi1_name = _wcsdup(data[0].c_str());

    if (data.size() > 1) {
        gi.grpi1_comment = _wcsdup(data[1].c_str());
    } else {
        gi.grpi1_comment = NULL;
    }

    return gi;
}

void GroupsInfo::printAccountRights(LSA_HANDLE policyHandle, PSID accountSid) {
    PLSA_UNICODE_STRING rights = NULL;
    ULONG rightsCount = 0;
    
    NTSTATUS status = LsaEnumerateAccountRights(policyHandle, accountSid, &rights, &rightsCount);
    if (status != 0) {
        wprintf(L"[ERROR] Failed to retrieve privileges (code: %x)\n", status);
        return;
    }

    wprintf(L"\tPrivileges:\n");
    for (ULONG i = 0; i < rightsCount; i++) {
        wprintf(L"\t\t%s (Enabled)\n", rights[i].Buffer);
    }

    LsaFreeMemory(rights);
}

bool GroupsInfo::GetGroups() {
    DWORD totalEntries = 0;
    if (NetLocalGroupEnum(NULL, 0, (LPBYTE*)&pBufGroups, MAX_PREFERRED_LENGTH, &entriesReadGroups, &totalEntries, NULL) != NERR_Success) {
        wprintf(L"[ERROR] Failed to retrieve group list.\n");
        return false;
    }
    return true;
}

void GroupsInfo::PrintGroupsInfo() {
    if (!pBufGroups) {
        wprintf(L"Group list is empty.\n");
        return;
    }

    LSA_HANDLE policyHandle = NULL;
    LSA_OBJECT_ATTRIBUTES objectAttributes = { 0 };
    objectAttributes.Length = sizeof(objectAttributes);

    if (LsaOpenPolicy(NULL, &objectAttributes, POLICY_LOOKUP_NAMES, &policyHandle) != 0) {
        wprintf(L"[ERROR] Failed to open security policy.\n");
        return;
    }

    for (DWORD i = 0; i < entriesReadGroups; i++) {
        LPLOCALGROUP_INFO_1 pBuf1 = NULL;
        LPBYTE pBufDetail = NULL;
        NET_API_STATUS nStatus = NetLocalGroupGetInfo(NULL, pBufGroups[i].lgrpi0_name, 1, &pBufDetail);

        if (nStatus == NERR_Success && pBufDetail) {
            pBuf1 = (LPLOCALGROUP_INFO_1)pBufDetail;
            wprintf(L"Group: %s\n", pBuf1->lgrpi1_name);
            wprintf(L"Comment: %s\n", pBuf1->lgrpi1_comment);

            BYTE sidBuffer[SECURITY_MAX_SID_SIZE]; // Buffer for SID
            DWORD sidSize = sizeof(sidBuffer);
            WCHAR domainName[MAX_PATH];
            DWORD domainSize = MAX_PATH;
            SID_NAME_USE sidType;

            if (LookupAccountNameW(NULL, pBuf1->lgrpi1_name, sidBuffer, &sidSize, domainName, &domainSize, &sidType)) {
                printAccountRights(policyHandle, (PSID)sidBuffer);
            } else {
                wprintf(L"[ERROR] Failed to retrieve SID for group %s (error: %d)\n", pBuf1->lgrpi1_name, GetLastError());
            }

            NetApiBufferFree(pBufDetail);
        } else {
            wprintf(L"[ERROR] Failed to retrieve group information for %s (code: %d)\n", pBufGroups[i].lgrpi0_name, nStatus);
        }
    }

    LsaClose(policyHandle);
}

bool GroupsInfo::AddGroup(const std::vector<std::wstring>& groupData) {
    if (groupData.empty()) {
        std::wcerr << L"[ERROR] Not enough parameters in groupData\n";
        return false;
    }

    GROUP_INFO_1 gi = {0};
    gi.grpi1_name = const_cast<LPWSTR>(groupData[0].c_str()); // Имя группы

    if (groupData.size() > 1) {
        gi.grpi1_comment = const_cast<LPWSTR>(groupData[1].c_str()); // Описание группы (если есть)
    }

    NET_API_STATUS status = NetLocalGroupAdd(NULL, 1, (LPBYTE)&gi, NULL);
    if (status != NERR_Success) {
        std::wcerr << L"[ERROR] Failed to add group: " << status << L"\n";
        return false;
    }

    std::wcout << L"[INFO] Group '" << groupData[0] << L"' added successfully.\n";
    return true;
}

bool GroupsInfo::DeleteGroup(const std::wstring& groupName) {
    if (groupName.empty()) {
        std::wcerr << L"[ERROR] Group name is empty\n";
        return false;
    }

    NET_API_STATUS status = NetLocalGroupDel(NULL, groupName.c_str());
    if (status != NERR_Success) {
        std::wcerr << L"[ERROR] Failed to delete group: " << status << L"\n";
        return false;
    }

    std::wcout << L"[INFO] Group '" << groupName << L"' deleted successfully.\n";
    return true;
}