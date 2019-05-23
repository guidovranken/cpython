#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <optional>

namespace fuzzing {

class Python {
    private:
        std::string code;
        std::string toPythonArrayString(const std::string variableName, const std::vector<uint8_t>& data);
    public:
        Python(const std::string argv0, const std::string scriptPath);
        std::optional<std::vector<uint8_t>> Run(const std::vector<uint8_t>& data);
};

} /* namespace fuzzing */
