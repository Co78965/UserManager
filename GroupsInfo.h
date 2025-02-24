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
};

#endif