#include "Settings.h"
#include "Util.h"

#include "FuncWatch.h"

#include <vector>
#include <fstream>
#include <sstream>

#define DELIM '='

#define KEY_FOLLOW_SHELLCODES           "FOLLOW_SHELLCODES"
#define KEY_FOLLOW_CHILDPROCESSES       "FOLLOW_CHILDPROCESSES"
#define KEY_LOG_RTDSC                   "TRACE_RDTSC"
#define KEY_LOG_INT                     "TRACE_INT"
#define KEY_LOG_SYSCALL                 "TRACE_SYSCALL"
#define KEY_LOG_SECTIONS_TRANSITIONS    "LOG_SECTIONS_TRANSITIONS"
#define KEY_LOG_SHELLCODES_TRANSITIONS  "LOG_SHELLCODES_TRANSITIONS"
#define KEY_SHORT_LOGGING               "ENABLE_SHORT_LOGGING"
#define HEXDUMP_SIZE                    "HEXDUMP_SIZE"
#define SLEEP_TIME                      "SLEEP_TIME"
#define HOOK_SLEEP                      "HOOK_SLEEP"
#define LOG_INDIRECT                    "LOG_INDIRECT_CALLS"
#define KEY_ANTIDEBUG                   "ANTIDEBUG"
#define KEY_ANTIVM                      "ANTIVM"
#define KEY_USE_DEBUG_SYMBOLS           "USE_DEBUG_SYMBOLS"
#define KEY_HYPREV_SET                  "EMULATE_HYPERV"
#define KEY_STOP_OFFSET_TIME            "STOP_OFFSET_TIME"
#define KEY_EMULATE_SINGLE_STEP         "EMULATE_SINGLE_STEP"
#define KEY_DISASM_CTX                  "DISASM_CTX"
#define KEY_DISASM_OUTER                "DISASM_OUTER"
#define KEY_LOG_RETURN_VALUE            "LOG_RETURN_VALUE"
#define KEY_FOLLOW_ARGS_RETURN          "FOLLOW_ARGS_RETURN"
#define KEY_PARSE_EXPORTS               "PARSE_EXPORTS"
#define KEY_VOLUME_ID                   "VOLUME_ID"

t_shellc_options ConvertShcOption(int value)
{
    if (value >= SHELLC_OPTIONS_COUNT) {
        // choose the last option:
        return t_shellc_options(SHELLC_OPTIONS_COUNT - 1);
    }
    return (t_shellc_options)value;
}

//----

std::string SyscallsTable::getName(int syscallID)
{
    auto found = syscallToFuncName.find(syscallID);
    if (found == syscallToFuncName.end()) {
        return "";
    }
    return found->second;
}

size_t SyscallsTable::load(const std::string& filename)
{
    std::ifstream myfile(util::stripQuotes(filename).c_str());
    if (!myfile.is_open()) {
        return 0;
    }
    const size_t MAX_LINE = 300;
    char line[MAX_LINE] = { 0 };

    while (!myfile.eof()) {
        myfile.getline(line, MAX_LINE);
        std::string lineStr = line;
        size_t found = lineStr.find_first_of(",");
        if (found != std::string::npos) {

            std::string numId = lineStr.substr(0, found);
            std::string funcName = lineStr.substr(found + 1);
            int syscallId = util::loadInt(numId, true);

            syscallToFuncName[syscallId] = funcName;
        }
    }
    myfile.close();
    return syscallToFuncName.size();
}
//----

bool StopOffset::load(const std::string& sline, char delimiter)
{
    std::vector<std::string> args;
    util::splitList(sline, delimiter, args);
    if (!args.size()) return false;

    this->rva = util::loadInt(args[0], true);
    if (!this->rva) {
        return false;
    }
    // optional argument:
    if (args.size() >= 2) {
        this->times = util::loadInt(args[1], false);
    }
    return true;
}

//---

bool loadBoolean(const std::string &str)
{
    if (util::iequals(str, "True") || util::iequals(str, "on") || util::iequals(str, "yes")) {
        return true;
    }
    if (util::iequals(str, "False") || util::iequals(str, "off") || util::iequals(str, "no")) {
        return false;
    }
    const int val = util::loadInt(str);
    if (val == 0) return false;
    return true;
}

std::string booleanToStr(const bool &val)
{
    return (val) ? "True" : "False";
}

bool parseRange(const std::string &token, std::set<DisasmRange>& disasmRanges)
{
    const char delim = ',';

    size_t rangeCount = 0;
    std::stringstream pairStream(token);
    std::string startHex, endHex;
    std::string rangeName;

    if (std::getline(pairStream, startHex, delim) && (std::getline(pairStream, endHex, delim) || std::getline(pairStream, endHex))) {
        rangeCount++;
        if (!std::getline(pairStream, rangeName)) {
            std::stringstream ss;
            ss << "Range_" << std::dec << rangeCount;
            rangeName = ss.str();
        }
        int start = util::loadInt(startHex, true);
        if (start == 0) return false;
        int stop = util::loadInt(endHex, true);

        DisasmRange r(start, stop, rangeName);
        disasmRanges.insert(r);
        return true;
    }
    return false;
}

std::string rangesToStr(const std::set<DisasmRange>& disasmRanges)
{
    std::stringstream ss;
    for (auto itr = disasmRanges.begin(); itr != disasmRanges.end(); ++itr) {
        ss << "[" << std::hex << itr->start << "," << itr->stop << "]";
    }
    return ss.str();
}

bool fillSettings(Settings &s, const std::string &line)
{
    std::vector<std::string> args;
    util::splitList(line, DELIM, args);

    if (args.size() < 2) {
        return false;
    }
    bool isFilled = false;
    std::string valName = args[0];
    std::string valStr = args[1];
    util::trim(valName);
    util::trim(valStr);

    if (util::iequals(valName, KEY_FOLLOW_SHELLCODES)) {
        const int val = util::loadInt(valStr);
        s.followShellcode = ConvertShcOption(val);
        isFilled = true;
    }
    if (util::iequals(valName, KEY_FOLLOW_CHILDPROCESSES)) {
        s.followChildprocesses = loadBoolean(valStr);
        isFilled = true;
    }
    if (util::iequals(valName, KEY_LOG_RTDSC)) {
        s.traceRDTSC = loadBoolean(valStr);
        isFilled = true;
    }
    if (util::iequals(valName, KEY_LOG_INT)) {
        s.traceINT = loadBoolean(valStr);
        isFilled = true;
    }
    if (util::iequals(valName, KEY_LOG_SYSCALL)) {
        s.traceSYSCALL = loadBoolean(valStr);
        isFilled = true;
    }
    if (util::iequals(valName, KEY_LOG_SECTIONS_TRANSITIONS)) {
        s.logSectTrans = loadBoolean(valStr);
        isFilled = true;
    }
    if (util::iequals(valName, KEY_LOG_SHELLCODES_TRANSITIONS)) {
        s.logShelcTrans = loadBoolean(valStr);
        isFilled = true;
    }
    if (util::iequals(valName, KEY_SHORT_LOGGING)) {
        s.shortLogging = loadBoolean(valStr);
        isFilled = true;
    }
    if (util::iequals(valName, HEXDUMP_SIZE)) {
        s.hexdumpSize = util::loadInt(valStr);
        isFilled = true;
    }
    if (util::iequals(valName, LOG_INDIRECT)) {
        s.logIndirect = loadBoolean(valStr);
        isFilled = true;
    }
    if (util::iequals(valName, HOOK_SLEEP)) {
        s.hookSleep = loadBoolean(valStr);
        isFilled = true;
    }
    if (util::iequals(valName, SLEEP_TIME)) {
        s.sleepTime = util::loadInt(valStr);
        isFilled = true;
    }
    if (util::iequals(valName, KEY_STOP_OFFSET_TIME)) {
        s.stopOffsetTime = util::loadInt(valStr);
        isFilled = true;
    }
    if (util::iequals(valName, KEY_ANTIDEBUG)) {
        const int val = util::loadInt(valStr);
        s.antidebug = ConvertWatchLevel(val);
        isFilled = true;
    }
    if (util::iequals(valName, KEY_ANTIVM)) {
        const int val = util::loadInt(valStr);
        s.antivm = ConvertWatchLevel(val);
        isFilled = true;
    }
    if (util::iequals(valName, KEY_USE_DEBUG_SYMBOLS)) {
        s.useDebugSym = loadBoolean(valStr);
        isFilled = true;
    }
    if (util::iequals(valName, KEY_HYPREV_SET)) {
        s.isHyperVSet = loadBoolean(valStr);
        isFilled = true;
    }
    if (util::iequals(valName, KEY_EMULATE_SINGLE_STEP)) {
        s.emulateSingleStep = loadBoolean(valStr);
        isFilled = true;
    }
    if (util::iequals(valName, KEY_DISASM_CTX)) {
        s.disasmCtx = loadBoolean(valStr);
        isFilled = true;
    }
    if (util::iequals(valName, KEY_DISASM_OUTER)) {
        s.disasmOuter = loadBoolean(valStr);
        isFilled = true;
    }
    if (util::iequals(valName, KEY_LOG_RETURN_VALUE)) {
        s.logReturn = loadBoolean(valStr);
        isFilled = true;
    }
    if (util::iequals(valName, KEY_FOLLOW_ARGS_RETURN)) {
        s.followArgReturn = loadBoolean(valStr);
        isFilled = true;
    }
    if (util::iequals(valName, KEY_PARSE_EXPORTS)) {
        s.parseExports = loadBoolean(valStr);
        isFilled = true;
    }
    if (util::iequals(valName, KEY_VOLUME_ID)) {
        s.volumeID = util::loadInt(valStr, true);
        isFilled = true;
    }
    return isFilled;
}

void Settings::stripComments(std::string &str)
{
    size_t found = str.find_first_of(";#");
    if (found != std::string::npos) {
        str.resize(found);
    }
}

size_t Settings::loadOffsetsList(const char* filename, std::set<StopOffset>& offsetsList)
{
    std::ifstream myfile(filename);
    if (!myfile.is_open()) {
        std::cerr << "Failed to open file: " << filename << std::endl;
        return 0;
    }
    const size_t MAX_LINE = 300;
    char line[MAX_LINE] = { 0 };
    while (!myfile.eof()) {
        myfile.getline(line, MAX_LINE);
        std::string str = line;
        if (!str.size() || str[0] == '#') { // skip empty lines and comments
            continue;
        }
        StopOffset so;
        if (so.load(str, LIST_DELIMITER)) {
            offsetsList.insert(so);
        }
    }
    return offsetsList.size();
}


size_t Settings::loadCustomDefs(const char* filename, std::map<ADDRINT, std::string>& customDefs)
{
    std::ifstream myfile(filename);
    if (!myfile.is_open()) {
        return 0;
    }
    const size_t MAX_LINE = 300;
    char line[MAX_LINE] = { 0 };
    while (!myfile.eof()) {
        myfile.getline(line, MAX_LINE);
        std::string sline = line;
        util::trim(sline);
        if (!sline.size() || sline[0] == '#') { // skip empty lines and comments
            continue;
        }

        std::vector<std::string> args;
        util::splitList(sline, ',', args);
        if (args.size() < 2) break;

        ADDRINT rva = util::loadInt(args[0], true);
        std::string name = args[1];
        customDefs[rva] = name;
    }
    return customDefs.size();
}

size_t Settings::loadDisasmRanges(const char* filename, std::set<DisasmRange>& disasmRanges)
{
    std::ifstream myfile(filename);
    if (!myfile.is_open()) {
        return 0;
    }
    const size_t MAX_LINE = 300;
    char line[MAX_LINE] = { 0 };
    while (!myfile.eof()) {
        myfile.getline(line, MAX_LINE);
        std::string sline = line;
        util::trim(sline);
        if (!sline.size() || sline[0] == '#') { // skip empty lines and comments
            continue;
        }
        parseRange(sline, disasmRanges);
    }
    return disasmRanges.size();
}

bool Settings::saveINI(const std::string &filename)
{
    std::ofstream myfile(filename.c_str());
    if (!myfile.is_open()) {
        return false;
    }
    myfile << KEY_FOLLOW_SHELLCODES << DELIM << this->followShellcode << "\r\n";
    myfile << KEY_FOLLOW_CHILDPROCESSES << DELIM << this->followChildprocesses << "\r\n";
    myfile << KEY_LOG_RTDSC << DELIM << booleanToStr(this->traceRDTSC) << "\r\n";
    myfile << KEY_LOG_INT << DELIM << booleanToStr(this->traceINT) << "\r\n";
    myfile << KEY_LOG_SYSCALL << DELIM << booleanToStr(this->traceSYSCALL) << "\r\n";
    myfile << KEY_LOG_SECTIONS_TRANSITIONS << DELIM << booleanToStr(this->logSectTrans) << "\r\n";
    myfile << KEY_LOG_SHELLCODES_TRANSITIONS << DELIM << booleanToStr(this->logShelcTrans) << "\r\n";
    myfile << KEY_SHORT_LOGGING << DELIM << booleanToStr(this->shortLogging) << "\r\n";
    myfile << KEY_USE_DEBUG_SYMBOLS << DELIM << booleanToStr(this->useDebugSym) << "\r\n";
    myfile << HEXDUMP_SIZE << DELIM << std::dec << this->hexdumpSize << "\r\n";
    myfile << HOOK_SLEEP << DELIM << std::dec << booleanToStr(this->hookSleep) << "\r\n";
    myfile << SLEEP_TIME << DELIM << std::dec << this->sleepTime << "\r\n";
    myfile << LOG_INDIRECT << DELIM << booleanToStr(this->logIndirect) << "\r\n";
    myfile << KEY_ANTIDEBUG << DELIM << this->antidebug << "\r\n";
    myfile << KEY_ANTIVM << DELIM << this->antivm << "\r\n";
    myfile << KEY_HYPREV_SET << DELIM << booleanToStr(this->isHyperVSet) << "\r\n";
    myfile << KEY_STOP_OFFSET_TIME << DELIM << std::dec << this->stopOffsetTime << "\r\n";
    myfile << KEY_EMULATE_SINGLE_STEP << DELIM << std::dec << booleanToStr(this->emulateSingleStep) << "\r\n";
    myfile << KEY_DISASM_CTX << DELIM << std::dec << booleanToStr(this->disasmCtx) << "\r\n";
    myfile << KEY_DISASM_OUTER << DELIM << std::dec << booleanToStr(this->disasmOuter) << "\r\n";
    myfile << KEY_LOG_RETURN_VALUE << DELIM << std::dec << booleanToStr(this->logReturn) << "\r\n";
    myfile << KEY_FOLLOW_ARGS_RETURN << DELIM << std::dec << booleanToStr(this->followArgReturn) << "\r\n";
    myfile << KEY_PARSE_EXPORTS << DELIM << std::dec << booleanToStr(this->parseExports) << "\r\n";
    myfile << KEY_VOLUME_ID << DELIM << std::hex << this->volumeID << "\r\n";
    myfile.close();
    return true;
}

bool Settings::loadINI(const std::string &filename)
{
    std::ifstream myfile(filename.c_str());
    if (!myfile.is_open()) {
        return false;
    }
    const size_t MAX_LINE = 300;
    char line[MAX_LINE] = { 0 };
    bool filledAny = false;

    while (!myfile.eof()) {
        myfile.getline(line, MAX_LINE);
        std::string lineStr = line;
        stripComments(lineStr);
        
        if (fillSettings(*this, lineStr)) {
            filledAny = true;
        }
    }
    myfile.close();
    return filledAny;
}

size_t Settings::loadExcluded(const char* excludedList)
{
    this->excludedFuncs.loadList(excludedList);

    std::ifstream myfile(excludedList);
    if (!myfile.is_open()) {
        return 0;
    }
    size_t dllsCount = 0;
    const size_t MAX_LINE = 300;
    char line[MAX_LINE] = { 0 };
    while (!myfile.eof()) {
        myfile.getline(line, MAX_LINE);

        if (strchr(line, LIST_DELIMITER) != nullptr) {
            continue;
        }
        this->excludedDll.insert(line);
        dllsCount++;
    }
    return dllsCount;
}

