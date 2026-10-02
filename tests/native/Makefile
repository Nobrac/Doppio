# Native tests of totp.cpp and verify.cpp on Linux (g++ and OpenSSL).
#   make -C tests/native
ROOT     := ../..
CXXFLAGS := -std=c++17 -Wall -Wextra -Wno-unknown-pragmas -Ishim -I$(ROOT) -I.
SOURCES  := test_verify.cpp fakes.cpp $(ROOT)/totp.cpp $(ROOT)/verify.cpp

.PHONY: test clean
test: test_verify
	./test_verify

test_verify: $(SOURCES) fakes.h shim/windows.h shim/bcrypt.h
	$(CXX) $(CXXFLAGS) $(SOURCES) -lcrypto -o $@

clean:
	rm -f test_verify
