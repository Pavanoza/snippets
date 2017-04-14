#pragma once

#include <windows.h>

#include <stdio.h> 
#include <string>
#include <vector>
#include <map>
#include <set>

std::string getLocalClasses();

size_t hijackExtensions(std::string proxy_path);

std::set<std::string> getGlobalCommands();
size_t rewriteExtensions(std::string &local, std::set<std::string> &handlersSets);