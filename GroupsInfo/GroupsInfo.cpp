#include "GroupsInfo.h"

GROUP_INFO_1 GroupsInfo::parseData(const std::vector<std::wstring>& data) {
    GROUP_INFO_1 gi = {0};
    if (data.empty()) {
        debug(L"Not enough parameters in groupData. Error code: " + std::to_wstring(GetLastError()), ERROR);
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

PSID GroupsInfo::getPSID(std::wstring groupName){
    PSID groupPSID = nullptr;
    DWORD sidSize = 0, domainSize = 0;
    SID_NAME_USE sidType;

    LookupAccountNameW(NULL, groupName.c_str(), NULL, &sidSize, NULL, &domainSize, &sidType);
    groupPSID = (PSID)malloc(sidSize);
    wchar_t* domainName = new wchar_t[domainSize];

    if (!LookupAccountNameW(NULL, groupName.c_str(), groupPSID, &sidSize, domainName, &domainSize, &sidType)) {
        debug(L"LookupAccountNameW failed for group " + groupName + L". Error code: " + std::to_wstring(GetLastError()), ERROR);
        free(groupPSID);
        delete[] domainName;
    }
    return groupPSID;
}

LSA_HANDLE GroupsInfo::getPolicy(){
    LSA_HANDLE policyHandle = NULL;
    LSA_OBJECT_ATTRIBUTES objectAttributes = { 0 };
    objectAttributes.Length = sizeof(objectAttributes);

    NTSTATUS status = LsaOpenPolicy(NULL, &objectAttributes, POLICY_LOOKUP_NAMES, &policyHandle);
    if (status != 0) {
        debug(L"Failed to open security policy. NTSTATUS: " + std::to_wstring(status), ERROR);
        return NULL;
    }
    return policyHandle;
}

void GroupsInfo::PrintAccountRights(std::wstring name, std::wstring text) {
    LSA_HANDLE policyHandle = getPolicy();
    PSID accountSid = getPSID(name);
    
    PLSA_UNICODE_STRING rights = NULL;
    ULONG rightsCount = 0;
    
    wprintf(L"\t%s\n", text.c_str());
    
    NTSTATUS status = LsaEnumerateAccountRights(policyHandle, accountSid, &rights, &rightsCount);
    auto s = L"\t\t";
    if(wcscmp(text.c_str(), L"\tInherited privileges:") == 0){
        s = L"\t\t\t";
    }

    if (status != 0) {
        wprintf(L"%sThe group has no privileges!", s);
        return;
    }

    for (ULONG i = 0; i < rightsCount; i++) {
        wprintf(L"%s%s (Enabled)\n", s, rights[i].Buffer);
    }

    LsaFreeMemory(rights);
}

LPWSTR GroupsInfo::convertSID(BYTE* sidBuffer){
    LPWSTR sidString = NULL;
    if (ConvertSidToStringSidW((PSID)sidBuffer, &sidString)) {
        return sidString;
    } else {
        debug(L"Error when converting SID. Error code: " + std::to_wstring(GetLastError()), ERROR);
        return L"NULL";
    }
}

int GroupsInfo::setInfo(const std::wstring& oldGroupName, LPBYTE groupInfo, int level){
    NET_API_STATUS status = NetLocalGroupSetInfo(NULL, oldGroupName.c_str(), level, groupInfo, NULL);
    
    if (status == NERR_Success) {
        debug(L"Successfully changed group info for '" + oldGroupName + L"'", INFO);
        return 0;
    } else {
        debug(L"NetLocalGroupSetInfo failed for group '" + oldGroupName + L"'. Error code: " + std::to_wstring(status), ERROR);
        return status;
    }
}

bool GroupsInfo::GetGroups() {
    DWORD totalEntries = 0;
    NET_API_STATUS status = NetLocalGroupEnum(NULL, 0, (LPBYTE*)&pBufGroups, MAX_PREFERRED_LENGTH, &entriesReadGroups, &totalEntries, NULL);
    if (status != NERR_Success) {
        debug(L"Failed to retrieve group list. Error code: " + std::to_wstring(status), ERROR);
        return false;
    }
    return true;
}

void GroupsInfo::PrintGroupInfo(std::wstring name){
    wprintf(L"\n----------------------------------------%s's info----------------------------------------\n", name.c_str());   
    LPLOCALGROUP_INFO_1 pBuf1 = NULL;
    LPBYTE pBufDetail = NULL;
    NET_API_STATUS nStatus = NetLocalGroupGetInfo(NULL, name.c_str(), 1, &pBufDetail);

    if (nStatus == NERR_Success && pBufDetail) {
        pBuf1 = (LPLOCALGROUP_INFO_1)pBufDetail;
        wprintf(L"Group: %s\n", pBuf1->lgrpi1_name);
        wprintf(L"\tComment: %s\n", pBuf1->lgrpi1_comment);

        BYTE sidBuffer[SECURITY_MAX_SID_SIZE];
        DWORD sidSize = sizeof(sidBuffer);
        WCHAR domainName[MAX_PATH];
        DWORD domainSize = MAX_PATH;
        SID_NAME_USE sidType;

        if (LookupAccountNameW(NULL, pBuf1->lgrpi1_name, sidBuffer, &sidSize, domainName, &domainSize, &sidType)) {
            wprintf(L"\tSID: %s\n", convertSID(sidBuffer));
            PrintAccountRights(name);
        } else {
            debug(L"Failed to retrieve SID for group " + std::wstring(pBuf1->lgrpi1_name) + L". Error code: " + std::to_wstring(GetLastError()), ERROR);
        }

        NetApiBufferFree(pBufDetail);
    } else {
        debug(L"Failed to retrieve group information for " + name + L". Error code: " + std::to_wstring(nStatus), ERROR);
    }
    wprintf(L"\n------------------------------------------------------------------------------------------\n");
}

void GroupsInfo::PrintGroupsInfo() {
    if (!pBufGroups) {
        debug(L"Group list is empty.", INFO);
        return;
    }

    LSA_HANDLE policyHandle = getPolicy();
    if (!policyHandle) {
        return;
    }

    wprintf(L"\n----------------------------------------Groups info----------------------------------------\n");
    for (DWORD i = 0; i < entriesReadGroups; i++) {
        PrintGroupInfo(pBufGroups[i].lgrpi0_name);
    }

    LsaClose(policyHandle);
}

bool GroupsInfo::AddGroup(const std::vector<std::wstring>& groupData) {
    if (groupData.empty()) {
        debug(L"Not enough parameters in groupData", ERROR);
        return false;
    }

    GROUP_INFO_1 gi = {0};
    gi.grpi1_name = const_cast<LPWSTR>(groupData[0].c_str());

    if (groupData.size() > 1) {
        gi.grpi1_comment = const_cast<LPWSTR>(groupData[1].c_str());
    }

    NET_API_STATUS status = NetLocalGroupAdd(NULL, 1, (LPBYTE)&gi, NULL);
    if (status != NERR_Success) {
        debug(L"Failed to add group. Error code: " + std::to_wstring(status), ERROR);
        return false;
    }

    debug(L"Group '" + groupData[0] + L"' added successfully.", INFO);
    return true;
}

bool GroupsInfo::DeleteGroup(const std::wstring& groupName) {
    if (groupName.empty()) {
        debug(L"Group name is empty", ERROR);
        return false;
    }

    NET_API_STATUS status = NetLocalGroupDel(NULL, groupName.c_str());
    if (status != NERR_Success) {
        debug(L"Failed to delete group. Error code: " + std::to_wstring(status), ERROR);
        return false;
    }

    debug(L"Group '" + groupName + L"' deleted successfully.", INFO);
    return true;
}

bool GroupsInfo::ModifyGroup(const std::wstring& oldGroupName, const std::wstring& newGroupName, const std::wstring& newGroupComment){
    if(!newGroupName.empty()){
        LOCALGROUP_INFO_0 groupInfo0;
        groupInfo0.lgrpi0_name = const_cast<LPWSTR>(newGroupName.c_str());
        int status = setInfo(oldGroupName, (LPBYTE)&groupInfo0, 0);
        if(status != 0){
            return false;
        }
    }

    if(!newGroupComment.empty()){
        LOCALGROUP_INFO_1 groupInfo1;
        groupInfo1.lgrpi1_comment = const_cast<LPWSTR>(newGroupComment.c_str());
        int status = setInfo(oldGroupName, (LPBYTE)&groupInfo1, 1);
        if(status != 0){
            return false;
        }
    }
    return true;
}

bool GroupsInfo::AddGroupPrivilege(const std::wstring& groupName, const std::wstring& privilege) {
    PSID groupSID = getPSID(groupName);
    if (!groupSID) {
        return false;
    }

    LSA_HANDLE policyHandle = getPolicy();
    if (!policyHandle) {
        free(groupSID);
        return false;
    }

    LSA_UNICODE_STRING lsaString;
    lsaString.Buffer = const_cast<LPWSTR>(privilege.c_str());
    lsaString.Length = static_cast<USHORT>(privilege.length() * sizeof(WCHAR));
    lsaString.MaximumLength = lsaString.Length + sizeof(WCHAR);

    NTSTATUS status = LsaAddAccountRights(policyHandle, groupSID, &lsaString, 1);
    if (status != 0) {
        debug(L"LsaAddAccountRights failed for group " + groupName + L". NTSTATUS: " + std::to_wstring(status), ERROR);
    } else {
        debug(L"Privilege " + privilege + L" added successfully to group " + groupName, INFO);
    }

    LsaClose(policyHandle);
    free(groupSID);
    return status == 0;
}

bool GroupsInfo::RemoveGroupPrivilege(const std::wstring& groupName, const std::wstring& privilege) {
    PSID groupSID = getPSID(groupName);
    if (!groupSID) {
        return false;
    }

    LSA_HANDLE policyHandle = getPolicy();
    if (!policyHandle) {
        free(groupSID);
        return false;
    }

    LSA_UNICODE_STRING lsaString;
    lsaString.Buffer = const_cast<LPWSTR>(privilege.c_str());
    lsaString.Length = static_cast<USHORT>(privilege.length() * sizeof(WCHAR));
    lsaString.MaximumLength = lsaString.Length + sizeof(WCHAR);

    NTSTATUS status = LsaRemoveAccountRights(policyHandle, groupSID, FALSE, &lsaString, 1);
    if (status != 0) {
        debug(L"LsaRemoveAccountRights failed for group " + groupName + L". NTSTATUS: " + std::to_wstring(status), ERROR);
    } else {
        debug(L"Privilege " + privilege + L" removed successfully from group " + groupName, INFO);
    }

    LsaClose(policyHandle);
    free(groupSID);
    return status == 0;
}

void GroupsInfo::debug(std::wstring text, int type){
    if(!groupDebug){
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