#include <windows.h>
#include <ntsecapi.h>
#include <iostream>
#include <io.h>
#include <fcntl.h>
#include <sstream>

#include "UsersInfo/UsersInfo.h"
#include "GroupsInfo/GroupsInfo.h"

#pragma comment(lib, "Advapi32.lib")

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

  void ShowUserMenu(UsersInfo u) {
    int choice;
    do {
        std::wstring name; 
        std::vector<std::wstring> info = {L"",L""};
        std::wstring privilege;
        std::wstring inputPrivileges;
        std::wistringstream ss;

        std::wcout << L"\n=== User's Menu ===\n";
        std::wcout << L"1. Enable/disable debug\n";
        std::wcout << L"2. Print Users Info\n";
        std::wcout << L"3. Print User Info\n";
        std::wcout << L"4. Add User\n";
        std::wcout << L"5. Delete User\n";
        std::wcout << L"6. Add User to Group\n";
        std::wcout << L"7. Remove User from Group\n";
        std::wcout << L"8. Add User Privilege\n";
        std::wcout << L"9. Remove User Privilege\n";
        std::wcout << L"0. Back\n";
        std::wcout << L"Select a section: ";
        std::cin >> choice;

        switch (choice) {
            case 1: 
                u.DebugOnOff(); 
                break;
            case 2: 
                u.PrintUsersInfo(); 
                break;
            case 3: 
                std::wcout << L"Enter a user name: "; 
                std::wcin >> name; 
                u.PrintUserInfo(name); 
                break;
            case 4: 
                std::wcout << L"Enter a new user name: ";
                std::wcin >> info[0];
                std::wcout << L"Enter a new password: ";
                std::wcin >> info[1];
                u.AddUser(info);
                break;
            case 5: 
                std::wcout << L"Enter a user name: "; 
                std::wcin >> name; 
                u.DeleteUser(name); 
                break;
            case 6:
                std::wcout << L"Enter the user name: ";
                std::wcin >> info[0];
                std::wcout << L"Enter the group name: ";
                std::wcin >> info[1];
                u.AddUserToGroup(info[0], info[1]);
                break;
            case 7:
                std::wcout << L"Enter the user name: ";
                std::wcin >> info[0];
                std::wcout << L"Enter the group name: ";
                std::wcin >> info[1];
                u.DelUserToGroup(info[0], info[1]);
                break;
            case 8:
                std::wcout << L"Enter the user name: ";
                std::wcin >> info[0];
                for (const auto& _privilege : privileges) {
                    std::wcout << _privilege << std::endl;
                }
                std::wcout << L"Enter Privileges (separate with space): ";
                std::wcin.ignore();
                std::getline(std::wcin, inputPrivileges);

                ss.str(inputPrivileges);
                while (ss >> privilege) {
                    u.AddUserPrivilege(info[0], privilege);
                }
                break;
            case 9:
                std::wcout << L"Enter the user name: ";
                std::wcin >> info[0];
                u.PrintAccountRights(info[0]);
                std::wcout << L"Enter Privileges (separate with space): ";
                std::wcin.ignore();
                std::getline(std::wcin, inputPrivileges);

                ss.str(inputPrivileges);
                while (ss >> privilege) {
                    u.RemoveUserPrivilege(info[0], privilege);
                }
                break;
            case 0: 
                break;
            default: 
                std::wcout << L"Incorrect choice. Try again...\n";
        }

        std::cin.ignore();
        std::wcout << L"Enter key...";
        getchar();
        system("cls");

    } while (choice != 0);
}


void ShowGroupMenu(GroupsInfo g) {
    int choice;
    do {
        std::wstring name; 
        std::vector<std::wstring> info = {L"",L""};
        std::wstring privilege;
        std::wstring inputPrivileges;
        std::wistringstream ss;

        std::wcout << L"\n=== Group's Menu ===\n";
        std::wcout << L"1. Enable/disable debug\n";
        std::wcout << L"2. Print Groups Info\n";
        std::wcout << L"3. Print Group Info\n";
        std::wcout << L"4. Add Group\n";
        std::wcout << L"5. Delete Group\n";
        std::wcout << L"6. Modify Group\n";
        std::wcout << L"7. Add Group Privilege\n";
        std::wcout << L"8. Delete Group Privilege\n";
        std::wcout << L"0. Back\n";
        std::wcout << L"Select a section:";
        std::cin >> choice;

        switch (choice) {
            case 1: g.DebugOnOff(); break;
            case 2: g.PrintGroupsInfo(); break;
            case 3: std::wcout << L"Enter a group name: "; std::wcin>>name; g.PrintGroupInfo(name); break;
            case 4: 
                std::wcout << L"Enter a new group name: ";
                std::wcin>>info[0];
                std::wcout << L"Enter a new group comment (not necessary): ";
                std::wcin>>info[1];
                g.AddGroup(info);
                break;
            case 5: std::wcout << L"Enter a group name: "; std::wcin>>name; g.DeleteGroup(name); break;
            case 6: 
                std::wcout << L"Enter the old group name: ";
                std::wcin>>name;
                std::wcout << L"Enter a new group name (not necessary): ";
                std::wcin>>info[0];
                std::wcout << L"Enter a new group comment (not necessary): ";
                std::wcin>>info[1];
                g.ModifyGroup(name, info[0], info[1]);
                break;
            case 7:
                std::wcout << L"Enter the group name: ";
                std::wcin >> info[0];
                for (const auto& _privilege : privileges) {
                    std::wcout << _privilege << std::endl;
                }
                std::wcout << L"Enter Privileges (separate with space): ";
                std::wcin.ignore();
                std::getline(std::wcin, inputPrivileges);

                // ss.clear();
                ss.str(inputPrivileges);  // Сбрасываем строку и создаем поток
                while (ss >> privilege) {
                    g.AddGroupPrivilege(info[0], privilege);  // Для каждой привилегии вызываем метод
                }
                break;
            case 8:
                std::wcout << L"Enter the group name: ";
                std::wcin>>info[0];
                g.PrintAccountRights(info[0], L"Сurrent privileges");
                std::wcout << L"Enter Privileges (separate with space): ";
                std::wcin.ignore();
                std::getline(std::wcin, inputPrivileges);

                // ss.clear();
                ss.str(inputPrivileges);  // Сбрасываем строку и создаем поток
                while (ss >> privilege) {
                    g.RemoveGroupPrivilege(info[0], privilege);  // Для каждой привилегии вызываем метод
                }
                break;
                case 0: break;
                default: std::wcout << L"Неверный выбор. Повторите.\n";
        }
        std::cin.ignore();
        std::wcout << L"Enter key...";
        getchar();
        system("cls");
    } while (choice != 0);
}

int main() {
    _setmode(_fileno(stdout), _O_U8TEXT);
    int debug = 0;
    GroupsInfo g(debug);
    UsersInfo u(&g, debug);

    std::wcout << L"***debug is disabled***";

    if(!(u.GetUsers() && g.GetGroups())){
        std::wcout << L"[ERROR] u.GetUsers() && g.GetGroups()";
        return -1;
    }

    int mainChoice;
    do {
        std::wcout << L"\n=== MAIN MENU ===\n";
        std::wcout << L"1. Actions with users\n";
        std::wcout << L"2. Actions with groups\n";
        std::wcout << L"0. Exit\n";
        std::wcout << L"Select a section:";
        std::cin >> mainChoice;
        system("cls");
        switch (mainChoice) {
            case 1: ShowUserMenu(u); break;
            case 2: ShowGroupMenu(g); break;
            case 0: std::wcout << L"Exit...\n"; break;
            default: std::wcout << L"Wrong choice. Repeat it.\n";
        }
    } while (mainChoice != 0);

    return 0;
}

    // GroupsInfo groups(debug);
    // UsersInfo users(&groups, debug);

    // if (!(groups.GetGroups() && users.GetUsers())){
    //     wprintf(L"[ERROR] groups.GetGroups() && users.GetUsers()\n");
    //     return -1;
    // }

    // // users.PrintUserInfo(L"lyuga");
    // groups.AddGroup({L"NewTestGroup", L"new test group"});
    // users.AddUser({L"vanya", L"1", L""});
    // users.AddUserPrivilege(L"vanya",L"SeBackupPrivilege");
    // users.AddUserPrivilege(L"vanya",L"SeCreatePagefilePrivilege");
    // users.PrintUserInfo(L"vanya");

    // groups.AddGroupPrivilege(L"NewTestGroup",  L"SeAuditPrivilege");
    // groups.AddGroupPrivilege(L"NewTestGroup",  L"SeEnableDelegationPrivilege");
    // groups.PrintGroupInfo(L"NewTestGroup");

    // users.AddUserToGroup(L"vanya", L"NewTestGroup");
    // users.PrintUserInfo(L"vanya");

    // users.DeleteUser(L"vanya");
    // groups.DeleteGroup(L"NewTestGroup");

    // users.PrintUserInfo(L"vanya");
    // groups.PrintGroupInfo(L"NewTestGroup");
