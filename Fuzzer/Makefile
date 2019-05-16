all : python-fuzzer

python-fuzzer : fuzzer.cpp
	$(CXX) $(CXXFLAGS) -Wall -Wextra -fsanitize=fuzzer -I ../Include -I .. fuzzer.cpp ../libpython3.8.a -lutil -lpthread -o python-fuzzer
