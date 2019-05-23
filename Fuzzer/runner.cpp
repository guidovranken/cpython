#include <climits>
#include <cstdlib>
#include <iomanip>
#include <libgen.h>
#include <sstream>

#include "runner.h"

#define PY_SSIZE_T_CLEAN
#include <Python.h>

namespace fuzzing {

Python::Python(const std::string argv0, const std::string scriptPath) {
    std::string scriptRootPath;

    std::vector<uint8_t> program;
    FILE* fp = fopen(scriptPath.c_str(), "rb");
    if ( fp == nullptr ) {
        printf("Fatal error: Cannot open script: %s\n", scriptPath.c_str());
        abort();
    }

    fseek (fp, 0, SEEK_END);
    long length = ftell(fp);
    if ( length < 1 ) {
        printf("Fatal error: Cannot retrieve script file size\n");
        abort();
    }
    fseek (fp, 0, SEEK_SET);
    program.resize(length);
    if ( fread(program.data(), 1, length, fp) != static_cast<size_t>(length) ) {
        printf("Fatal error: Cannot read script\n");
        abort();
    }
    fclose(fp);

    code = std::string(program.data(), program.data() + program.size());

    {
        /* Resolve script root path */
        char resolved_path[PATH_MAX+1];
        if ( realpath(scriptPath.c_str(), resolved_path) == nullptr ) {
            printf("Fatal error: Cannot resolve full script path\n");
            abort();
        }
        scriptRootPath = std::string(dirname(resolved_path));
    }

    {
        wchar_t *program = Py_DecodeLocale(argv0.c_str(), nullptr);
        Py_SetProgramName(program);
    }

    Py_Initialize();

    {
        std::string setPYTHONPATH;
        setPYTHONPATH += "import sys";
        setPYTHONPATH += "\n";
        setPYTHONPATH += "sys.path.append('" + scriptRootPath + "')";
        setPYTHONPATH += "\n";
        if ( PyRun_SimpleString(setPYTHONPATH.c_str()) != 0 ) {
            printf("Fatal: Cannot set PYTHONPATH\n");
            abort();
        }

    }
}

std::string Python::toPythonArrayString(const std::string variableName, const std::vector<uint8_t>& data) {
    std::stringstream ss;

    ss << variableName << " = [";
    for (size_t i = 0; i < data.size(); i++) {
        ss << "0x" << std::hex << std::setfill('0') << std::setw(2) << (int)(data[i]) << ", ";
    }

    ss << "]";

    return ss.str() + "\n";
}

std::optional<std::vector<uint8_t>> Python::Run(const std::vector<uint8_t>& data) {
    std::string totalProgram;

    totalProgram += toPythonArrayString("FuzzerInput", data);
    totalProgram += code;

    if ( PyRun_SimpleString(totalProgram.c_str()) != 0 ) {
        /* Abort on unhandled exception */
        abort();
    }

    return std::nullopt;
}

} /* namespace fuzzing */
