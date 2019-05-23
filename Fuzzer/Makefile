all : runner.o python-fuzzer

CXXFLAGS+=-O3 -Wall -Wextra -DNDEBUG -fsanitize=fuzzer -std=c++17

CPYTHON_INSTALL_PATH=../../cpython-install
CPYTHON_LIB_PATH=$(CPYTHON_INSTALL_PATH)/lib/python3.8
CPYTHON_LIB_DYNLOAD_PATH=$(CPYTHON_LIB_PATH)/lib-dynload

# (paths to) dynamic libraries needed at runtime need to be linked into the binary
# See also: https://stackoverflow.com/questions/11842920/undefined-symbol-pyexc-importerror-when-embedding-python-in-c
DYNLOAD_LIBS=_hashlib _sha3 _blake2
DYNLOAD_LIBS_PATHS=$(addsuffix *.so,$(addprefix $(CPYTHON_LIB_DYNLOAD_PATH)/,$(DYNLOAD_LIBS)))

runner.o : runner.cpp
	$(CXX) $(CXXFLAGS) -c -I ../Include -I .. runner.cpp -o runner.o

python-fuzzer : fuzzer.cpp runner.o
	$(CXX) $(CXXFLAGS) -I ../Include -I .. fuzzer.cpp runner.o ../libpython3.8.a -lutil -lpthread $(DYNLOAD_LIBS_PATHS) -o python-fuzzer
