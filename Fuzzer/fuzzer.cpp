#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string.hpp>
#include <memory>
#include "runner.h"
#include "coverage.h"

std::unique_ptr<fuzzing::Python> python = nullptr;

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
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

            python = std::make_unique<fuzzing::Python>((*argv)[0], targetFilename);
            return 0;
        }
    }

    if ( python == nullptr ) {
        printf("No input file loaded. Specify with --program=<filename>\n");
        exit(1);
    }

    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    std::vector<uint8_t> v(data, data + size);

    python->Run(v);

    return 0;
}
