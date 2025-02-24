#ifndef GROUPS_INFO
#define GROUPS_INFO

#include <windows.h>
#include <stdio.h>
#include <lm.h>
#include <sddl.h>
#include <iostream>
#include <ntsecapi.h>
#include <vector>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "netapi32.lib")

class GroupsInfo{
    private:
        DWORD entriesReadGroups;
        LPLOCALGROUP_INFO_0 pBufGroups;

        GROUP_INFO_1 parseData(const std::vector<std::wstring>& data);
        void printAccountRights(LSA_HANDLE, PSID);
        LPWSTR convertSID(BYTE* sidBuffer);
        int setInfo(const std::wstring& oldGroupName, LPBYTE groupInfo, int level);
    public:
        GroupsInfo() : entriesReadGroups(0), pBufGroups(NULL) {}
        
        ~GroupsInfo() {
            if (pBufGroups) {
                NetApiBufferFree(pBufGroups);
            }
        }

        bool GetGroups();
        void PrintGroupsInfo();

        bool AddGroup(const std::vector<std::wstring>& groupData);
        bool DeleteGroup(const std::wstring& groupName);

        bool ModifyGroup(const std::wstring& oldGroupName, const std::wstring& newGroupName = L"", const std::wstring& newGroupComment = L"");
};

#endif