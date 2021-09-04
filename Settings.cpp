#include "Settings.h"
#include "Util.h"

#include <vector>
#include <fstream>
#include <sstream>

#define DELIM '='

#define KEY_FOLLOW_SHELLCODES           "FOLLOW_SHELLCODES"
#define KEY_LOG_RTDSC                   "TRACE_RDTSC"
#define KEY_LOG_SECTIONS_TRANSITIONS    "LOG_SECTIONS_TRANSITIONS"
#define KEY_LOG_SHELLCODES_TRANSITIONS  "LOG_SHELLCODES_TRANSITIONS"
#define KEY_SHORT_LOGGING               "ENABLE_SHORT_LOGGING"
#define HEXDUMP_SIZE                    "HEXDUMP_SIZE"

t_shellc_options ConvertShcOption(int value)
{
    if (value >= SHELLC_OPTIONS_COUNT) {
        // choose the last option:
        return t_shellc_options(SHELLC_OPTIONS_COUNT - 1);
    }
    return (t_shellc_options)value;
}

//----

bool loadBoolean(const std::string &str, bool defaultVal)
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

bool fillSettings(Settings &s, std::string line)
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
    if (util::iequals(valName, KEY_LOG_RTDSC)) {
        s.traceRDTSC = loadBoolean(valStr, s.traceRDTSC);
        isFilled = true;
    }
    if (util::iequals(valName, KEY_LOG_SECTIONS_TRANSITIONS)) {
        s.logSectTrans = loadBoolean(valStr, s.logSectTrans);
        isFilled = true;
    }
    if (util::iequals(valName, KEY_LOG_SHELLCODES_TRANSITIONS)) {
        s.logShelcTrans = loadBoolean(valStr, s.logShelcTrans);
        isFilled = true;
    }
    if (util::iequals(valName, KEY_SHORT_LOGGING)) {
        s.shortLogging = loadBoolean(valStr, s.shortLogging);
        isFilled = true;
    }
    if (util::iequals(valName, HEXDUMP_SIZE)) {
        s.hexdumpSize = util::loadInt(valStr);
        isFilled = true;
    }
    return isFilled;
}

void stripComments(std::string &str)
{
    size_t found = str.find_first_of(";#");
    if (found != std::string::npos) {
        str = str.substr(0, found - 1);
    }
}

bool Settings::saveINI(const std::string filename)
{
    std::ofstream myfile(filename.c_str());
    if (!myfile.is_open()) {
        return false;
    }
    myfile << KEY_FOLLOW_SHELLCODES << DELIM << this->followShellcode << "\r\n";
    myfile << KEY_LOG_RTDSC << DELIM << this->traceRDTSC << "\r\n";

    myfile << KEY_LOG_SECTIONS_TRANSITIONS << DELIM << this->logSectTrans << "\r\n";
    myfile << KEY_LOG_SHELLCODES_TRANSITIONS << DELIM << this->logShelcTrans << "\r\n";
    myfile << KEY_SHORT_LOGGING << DELIM << this->shortLogging << "\r\n";
    myfile << HEXDUMP_SIZE << DELIM << this->hexdumpSize << "\r\n";
    myfile.close();
    return true;
}

bool Settings::loadINI(const std::string filename)
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
    return filledAny;
}
