#ifndef USERS_INFO
#define USERS_INFO

#include <windows.h>
#include <stdio.h>
#include <lm.h>
#include <sddl.h>
#include <iostream>
#include <ntsecapi.h>
#include <vector>
#include <winnt.h>
#include "../interface/IGroupsInfo.h"

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "netapi32.lib")

#define INFO (1)

class UsersInfo {
    private:
        IGroupsInfo* groups;
        int usersDebug;
        DWORD entriesReadUsers;
        LPUSER_INFO_0 pBufUsers;
        LPLOCALGROUP_INFO_0 pBufGroups;
    
        USER_INFO_1 parseData(const std::vector<std::wstring>& data);
        void printAccountRights(LSA_HANDLE,PSID);
        void debug(std::wstring text, int type);
        const std::vector<LPCWSTR> privileges = {
            L"SeAssignPrimaryTokenPrivilege",
            L"SeAuditPrivilege",
            L"SeBackupPrivilege",
            L"SeBatchLogonRight",
            L"SeChangeNotifyPrivilege",
            L"SeCreateGlobalPrivilege",
            L"SeCreatePagefilePrivilege",
            L"SeCreatePermanentPrivilege",
            L"SeCreateSymbolicLinkPrivilege",
            L"SeCreateTokenPrivilege",
            L"SeDebugPrivilege",
            L"SeDelegateSessionUserImpersonatePrivilege",
            L"SeDenyBatchLogonRight",
            L"SeDenyInteractiveLogonRight",
            L"SeDenyNetworkLogonRight",
            L"SeDenyRemoteInteractiveLogonRight",
            L"SeDenyServiceLogonRight",
            L"SeEnableDelegationPrivilege",
            L"SeImpersonatePrivilege",
            L"SeIncreaseBasePriorityPrivilege",
            L"SeIncreaseQuotaPrivilege",
            L"SeIncreaseWorkingSetPrivilege",
            L"SeInteractiveLogonRight",
            L"SeLoadDriverPrivilege",
            L"SeLockMemoryPrivilege",
            L"SeMachineAccountPrivilege",
            L"SeManageVolumePrivilege",
            L"SeNetworkLogonRight",
            L"SeProfileSingleProcessPrivilege",
            L"SeRelabelPrivilege",
            L"SeRemoteInteractiveLogonRight",
            L"SeRemoteShutdownPrivilege",
            L"SeRestorePrivilege",
            L"SeSecurityPrivilege",
            L"SeServiceLogonRight",
            L"SeShutdownPrivilege",
            L"SeSyncAgentPrivilege",
            L"SeSystemEnvironmentPrivilege",
            L"SeSystemProfilePrivilege",
            L"SeSystemtimePrivilege",
            L"SeTakeOwnershipPrivilege",
            L"SeTcbPrivilege",
            L"SeTimeZonePrivilege",
            L"SeTrustedCredManAccessPrivilege",
            L"SeUndockPrivilege"
          };
    public:
        UsersInfo(IGroupsInfo* groups, int debug) : usersDebug(debug), groups(groups), entriesReadUsers(0), pBufUsers(NULL), pBufGroups(NULL) {}
    
        ~UsersInfo() {
            if (pBufUsers) {
                NetApiBufferFree(pBufUsers);
            }
            if (pBufGroups) {
                NetApiBufferFree(pBufGroups);
            }
        }
    
        bool GetUsers();
        void PrintUsersInfo();
        void PrintUserInfo(std::wstring name);

        bool AddUser(const std::vector<std::wstring>& userData);
        bool DeleteUser(const std::wstring& userName);
        
        bool AddUserToGroup(const std::wstring& userName, const std::wstring& groupName);
        bool DelUserToGroup(const std::wstring& userName, const std::wstring& groupName);
        
        bool AddUserPrivilege(const std::wstring& username, const std::wstring& privilege);
        bool RemoveUserPrivilege(const std::wstring& username, const std::wstring& privilege);
    };

#endif