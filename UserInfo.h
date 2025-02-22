#ifndef USER_INFO
#define USER_INFO

#include <windows.h>
#include <stdio.h>
#include <lm.h>
#include <sddl.h>
#include <iostream>
#include <ntsecapi.h>
#include <vector>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "netapi32.lib")

#define USER  (0)
#define GROUP (1)

class UsersInfo {
    private:
        DWORD entriesReadUsers;
        DWORD entriesReadGroups;
        LPUSER_INFO_0 pBufUsers;
        LPLOCALGROUP_INFO_0 pBufGroups;
    
        USER_INFO_1 parseData(const std::vector<std::wstring>& userData, int FLAG = USER);
    
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
        void PrintAccountRights(LSA_HANDLE,PSID);
    
        bool AddUser(const std::vector<std::wstring>& userData);
        //bool AddGroup(); //NetGroupAdd
    
        bool DeleteUser(const std::wstring& username);
        //bool DelGroup(); //NetGroupDel
    
        //bool UserChange(); //NetUserSetInfo 
    
        //bool PrivelegiaChange(); //
    };

#endif