#ifndef USER_INFO
#define USER_INFO

#include <windows.h>
#include <stdio.h>
#include <lm.h>
#include <sddl.h>
#include <iostream>
#include <ntsecapi.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "netapi32.lib")

class UsersInfo {
    private:
        DWORD entriesReadUsers;
        DWORD entriesReadGroups;
        LPUSER_INFO_0 pBufUsers;
        LPLOCALGROUP_INFO_0 pBufGroups;
    
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
    
        //bool AddUser(); //NetUserAdd
        //bool AddGroup(); //NetGroupAdd
    
        //bool DelUser(); //NetUserDel
        //bool DelGroup(); //NetGroupDel
    
        //bool UserChange(); //NetUserSetInfo 
    
        //bool PrivelegiaChange(); //
    };

#endif