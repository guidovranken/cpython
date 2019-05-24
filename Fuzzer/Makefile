all : Makefile.linkflags runner.o python-fuzzer

CXXFLAGS+=-O3 -Wall -Wextra -DNDEBUG -std=c++17

CPYTHON_INSTALL_PATH=$(realpath ../../cpython-install)
CPYTHON_LIB_PATH=$(CPYTHON_INSTALL_PATH)/lib/python3.8
CPYTHON_LIB_DYNLOAD_PATH=$(CPYTHON_LIB_PATH)/lib-dynload

# (paths to) dynamic libraries needed at runtime need to be linked into the binary
# See also: https://stackoverflow.com/questions/11842920/undefined-symbol-pyexc-importerror-when-embedding-python-in-c
DYNLOAD_LIBS=_hashlib _sha3 _blake2
DYNLOAD_LIBS_PATHS=$(addsuffix *.so,$(addprefix $(CPYTHON_LIB_DYNLOAD_PATH)/,$(DYNLOAD_LIBS)))

PYTHON_FUZZER_LINK_FLAGS=$(realpath ../libpython3.8.a) -lutil -lpthread $(DYNLOAD_LIBS_PATHS)

Makefile.linkflags :
	echo "PYTHON_FUZZER_LINK_FLAGS=$(PYTHON_FUZZER_LINK_FLAGS)" >Makefile.linkflags

runner.o : runner.cpp
	$(CXX) $(CXXFLAGS) -fsanitize=fuzzer-no-link -c -I ../Include -I .. runner.cpp -o runner.o

python-fuzzer : fuzzer.cpp runner.o
	$(CXX) $(CXXFLAGS) -fsanitize=fuzzer -I ../Include -I .. fuzzer.cpp runner.o $(PYTHON_FUZZER_LINK_FLAGS) -o python-fuzzer
