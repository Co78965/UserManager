#ifndef _IGROUPSINFO_H_
#define _IGROUPSINFO_H_

#include <iostream>

class IGroupsInfo {
public:
    virtual ~IGroupsInfo() = default;
    virtual void PrintAccountRights(std::wstring name, std::wstring text) = 0;
};

#endif