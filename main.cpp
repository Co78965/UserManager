#include <iostream>
#include <vector>
#include <string>
#include "GroupsInfo.h"  // Подключаем заголовочный файл с реализацией класса GroupsInfo
#include <io.h>
#include <fcntl.h>

void TestGroupOperations() {
    GroupsInfo groups;
    // if (!groups.GetGroups()){
    //     std::wcout << L"[FAIL] Failed to get groups.\n";
    //     return; // Прерываем тест, если не удалось добавить
    // }
    
    // groups.PrintGroupsInfo();

    std::wstring testGroupName = L"TestGroup";
    std::wstring testGroupComment = L"Temporary test group";

    // Тест: Добавление группы
    std::wcout << L"\n\nTesting AddGroup...\n";
    if (groups.AddGroup({testGroupName, testGroupComment})) {
        std::wcout << L"[SUCCESS] Group added successfully.\n";
    } else {
        std::wcout << L"[FAIL] Failed to add group.\n\n";
        return; // Прерываем тест, если не удалось добавить
    }

    if (!groups.GetGroups()){
        std::wcout << L"[FAIL] Failed to get groups.\n";
        return; // Прерываем тест, если не удалось добавить
    }
    groups.PrintGroupsInfo();

    // Тест: Удаление группы
    std::wcout << L"\n\nTesting DeleteGroup...\n";
    if (groups.DeleteGroup(testGroupName)) {
        std::wcout << L"[SUCCESS] Group deleted successfully.\n";
    } else {
        std::wcout << L"[FAIL] Failed to delete group.\n\n";
    }

    if (!groups.GetGroups()){
        std::wcout << L"[FAIL] Failed to get groups.\n";
        return; // Прерываем тест, если не удалось добавить
    }
    groups.PrintGroupsInfo();
}

int main() {
    _setmode(_fileno(stdout), _O_U8TEXT);
    TestGroupOperations();
    return 0;
}