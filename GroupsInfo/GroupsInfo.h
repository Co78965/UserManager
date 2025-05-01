#ifndef GROUPS_INFO
#define GROUPS_INFO

#include <windows.h>
#include <stdio.h>
#include <lm.h>
#include <sddl.h>
#include <iostream>
#include <ntsecapi.h>
#include <vector>
#include "../interface/IGroupsInfo.h"
#include <string>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "netapi32.lib")

#define INFO (1)

class GroupsInfo : public IGroupsInfo{
    private:
        DWORD entriesReadGroups;
        LPLOCALGROUP_INFO_0 pBufGroups;
        int groupDebug;
        GROUP_INFO_1 parseData(const std::vector<std::wstring>& data);
        LPWSTR convertSID(BYTE* sidBuffer);
        int setInfo(const std::wstring& oldGroupName, LPBYTE groupInfo, int level);
        void debug(std::wstring text, int type);
        PSID getPSID(std::wstring groupName);
        LSA_HANDLE getPolicy();
    public:
        GroupsInfo(int debug) : groupDebug(debug), entriesReadGroups(0), pBufGroups(NULL) {}
        
        void PrintAccountRights(std::wstring name, std::wstring text = L"Privileges");
        
        ~GroupsInfo() {
            if (pBufGroups) {
                NetApiBufferFree(pBufGroups);
            }
        }

        bool GetGroups();
        void PrintGroupsInfo();
        void PrintGroupInfo(std::wstring name);

        bool AddGroup(const std::vector<std::wstring>& groupData);
        bool DeleteGroup(const std::wstring& groupName);

        bool ModifyGroup(const std::wstring& oldGroupName, const std::wstring& newGroupName = L"", const std::wstring& newGroupComment = L"");
        bool AddGroupPrivilege(const std::wstring& groupName, const std::wstring& privilegeName);
        bool RemoveGroupPrivilege(const std::wstring& groupName, const std::wstring& privilege);
    };

#endif