#pragma once

#include "pin.H"
#include <fstream>

size_t dumpFileExports(std::ofstream& fileStream, const IMG& img);
size_t dumpModuleExports(std::ofstream& fileStream, IMG& img);
size_t dumpModuleSymbols(std::ofstream& fileStream, IMG& img);
