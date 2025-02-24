#include <iostream>
#include <vector>
#include <string>
#include "GroupsInfo.h"  // Подключаем заголовочный файл с реализацией класса GroupsInfo
#include <io.h>
#include <fcntl.h>

void TestGroupOperations() {
    GroupsInfo groups;

    std::wstring oldGroupName = L"TestGroup";
    std::wstring newGroupName = L"NewTestGroup";

    groups.ModifyGroup(oldGroupName, newGroupName, L"New group");

    groups.GetGroups();
    groups.PrintGroupsInfo();
}

int main() {
    _setmode(_fileno(stdout), _O_U8TEXT);
    TestGroupOperations();
    return 0;
}