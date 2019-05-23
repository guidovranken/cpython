#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string.hpp> 
#include <sstream>
#include <iomanip>
#include <cstdio>
#include <cstdint>
#include <set>
#include <string>
#include <vector>

#define PY_SSIZE_T_CLEAN
#include <Python.h>

std::string target;
std::string thisprogram;

#define COVERAGE_ARRAY_SIZE 65536

extern "C" {
    __attribute__((section("__libfuzzer_extra_counters")))
    uint8_t coverage_counter[COVERAGE_ARRAY_SIZE];
}

extern "C" void global_record_code_coverage(const char* filename, const char* function, const int line)
{
    static std::hash<std::string> hasher;
    coverage_counter[ hasher(std::string(filename) + std::string(function) + std::to_string(line)) % COVERAGE_ARRAY_SIZE ] = 1;
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    bool inputFileLoaded = false;

    for (int i = 1; i < *argc; i++) {
        const std::string curArgument = std::string((*argv)[i]);

        if ( boost::starts_with(curArgument, "--program") ) {
            std::string targetFilename;
            {
                std::vector<std::string> parts;
                boost::split(parts, curArgument, boost::is_any_of("="));
                if ( parts.size() != 2 ) {
                    continue;
                }
                targetFilename = parts[1];
            }

            if ( targetFilename.empty() ) {
                continue;
            }

            std::vector<uint8_t> program;
            FILE* fp = fopen(targetFilename.c_str(), "rb");
            if ( fp == nullptr ) {
                printf("Cannot open %s\n", targetFilename.c_str());
                exit(1);
            }

            fseek (fp, 0, SEEK_END);
            long length = ftell(fp);
            fseek (fp, 0, SEEK_SET);
            program.resize(length);
            fread(program.data(), 1, length, fp);
            fclose(fp);
            target = std::string(program.data(), program.data() + program.size());

            inputFileLoaded = true;
        }
    }

    if ( inputFileLoaded == false ) {
        printf("No input file loaded. Specify with --program=<filename>\n");
        exit(1);
    }

    {
        wchar_t *program = Py_DecodeLocale((*argv)[0], nullptr);
        Py_SetProgramName(program);
    }

    Py_Initialize();

    return 0;
}

static std::string toPythonArrayString(const std::string variableName, const std::vector<uint8_t> data) {
    std::stringstream ss;

    ss << variableName << " = [";
    for (size_t i = 0; i < data.size(); i++) {
        ss << "0x" << std::hex << std::setfill('0') << std::setw(2) << (int)(data[i]) << ", ";
    }

    ss << "]";

    return ss.str() + "\n";
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

    std::string totalProgram;

    totalProgram += toPythonArrayString("FuzzerInput", std::vector<uint8_t>(data, data + size));
    totalProgram += target;

    if ( PyRun_SimpleString(totalProgram.c_str()) != 0 ) {
        /* Abort on unhandled exception */
        abort();
    }

    return 0;
}
