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

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "netapi32.lib")

class UsersInfo {
    private:
        DWORD entriesReadUsers;
        DWORD entriesReadGroups;
        LPUSER_INFO_0 pBufUsers;
        LPLOCALGROUP_INFO_0 pBufGroups;
    
        USER_INFO_1 parseData(const std::vector<std::wstring>& data);
        void printAccountRights(LSA_HANDLE,PSID);
    public:
        UsersInfo() : entriesReadUsers(0), entriesReadGroups(0), pBufUsers(NULL), pBufGroups(NULL) {}
    
        ~UsersInfo() {
            if (pBufUsers) {
                NetApiBufferFree(pBufUsers);
            }
            if (pBufGroups) {
                NetApiBufferFree(pBufGroups);
            }
        }
    
        bool GetUsers();
        bool GetGroups();
        void PrintUserInfo();
        void PrintGroupInfo();
    
        bool AddUser(const std::vector<std::wstring>& userData);
        bool DeleteUser(const std::wstring& userName);
        //bool DelGroup(); //NetGroupDel
    
        //bool UserChange(); //NetUserSetInfo 
    
        //bool PrivelegiaChange(); //
    };

#endif