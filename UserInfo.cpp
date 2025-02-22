#include "UserInfo.h"
#include <ntsecapi.h>
#include <winnt.h>
#include <windows.h>

void UsersInfo::PrintAccountRights(LSA_HANDLE policyHandle, PSID accountSid) {
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

bool UsersInfo::GetUsers() {
    DWORD totalEntries = 0;
    if (NetUserEnum(NULL, 0, FILTER_NORMAL_ACCOUNT, (LPBYTE*)&pBufUsers, MAX_PREFERRED_LENGTH, &entriesReadUsers, &totalEntries, NULL) != NERR_Success) {
        wprintf(L"[ERROR] Failed to retrieve user list.\n");
        return false;
    }
    return true;
}

bool UsersInfo::GetGroups() {
    DWORD totalEntries = 0;
    if (NetLocalGroupEnum(NULL, 0, (LPBYTE*)&pBufGroups, MAX_PREFERRED_LENGTH, &entriesReadGroups, &totalEntries, NULL) != NERR_Success) {
        wprintf(L"[ERROR] Failed to retrieve group list.\n");
        return false;
    }
    return true;
}

void UsersInfo::PrintUserInfo() {
    if (pBufUsers == NULL) {
        wprintf(L"User list is empty.\n");
        return;
    }

    LSA_HANDLE policyHandle = NULL;
    LSA_OBJECT_ATTRIBUTES objectAttributes = { 0 };
    objectAttributes.Length = sizeof(objectAttributes);

    if (LsaOpenPolicy(NULL, &objectAttributes, POLICY_LOOKUP_NAMES, &policyHandle) != 0) {
        wprintf(L"[ERROR] Failed to open security policy.\n");
        return;
    }

    for (DWORD i = 0; i < entriesReadUsers; i++) {
        LPUSER_INFO_4 pBuf4 = NULL;
        LPBYTE pBufDetail = NULL;
        NET_API_STATUS nStatus = NetUserGetInfo(NULL, pBufUsers[i].usri0_name, 4, &pBufDetail);

        if (nStatus == NERR_Success && pBufDetail) {
            pBuf4 = (LPUSER_INFO_4)pBufDetail;
            wprintf(L"User: %s\n", pBuf4->usri4_name);
            wprintf(L"\tPrivilege level: %s\n",
                (pBuf4->usri4_priv == USER_PRIV_GUEST) ? L"Guest" :
                (pBuf4->usri4_priv == USER_PRIV_USER) ? L"User" : L"Administrator");

            wprintf(L"\tFlags: 0x%x\n", pBuf4->usri4_flags);
            wprintf(L"\tPrimary group ID: %d\n", pBuf4->usri4_primary_group_id);

            PrintAccountRights(policyHandle, pBuf4->usri4_user_sid);
            NetApiBufferFree(pBufDetail);
        } else {
            wprintf(L"[ERROR] Failed to retrieve user information for %s (code: %d)\n", pBufUsers[i].usri0_name, nStatus);
        }
    }

    LsaClose(policyHandle);
}

void UsersInfo::PrintGroupInfo() {
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
                PrintAccountRights(policyHandle, (PSID)sidBuffer);
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
