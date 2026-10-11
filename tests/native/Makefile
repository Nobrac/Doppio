# Native tests on Linux (g++), no Windows needed:
#   test_verify - the real totp.cpp and verify.cpp, against OpenSSL and an
#                 in-memory store.
#   test_lsa    - the real subauth.cpp, ap.cpp and store_index.cpp (the code
#                 that runs inside lsass), against a fake registry, event log
#                 and LSA heap, under AddressSanitizer and UBSan.
#   make -C tests/native
ROOT     := ../..
CXXFLAGS := -std=c++17 -Wall -Wextra -Wno-unknown-pragmas -Ishim -I$(ROOT) -I.
SANITIZE := -g -fsanitize=address,undefined -fno-sanitize-recover=all

VERIFY_SOURCES := test_verify.cpp fakes.cpp $(ROOT)/totp.cpp $(ROOT)/verify.cpp
LSA_SOURCES    := test_lsa.cpp lsa_fakes.cpp $(ROOT)/subauth.cpp $(ROOT)/ap.cpp $(ROOT)/store_index.cpp
SHIMS          := $(wildcard shim/*.h)

.PHONY: test clean
test: test_verify test_lsa
	./test_verify
	./test_lsa

test_verify: $(VERIFY_SOURCES) fakes.h $(SHIMS)
	$(CXX) $(CXXFLAGS) $(VERIFY_SOURCES) -lcrypto -o $@

test_lsa: $(LSA_SOURCES) lsa_fakes.h $(SHIMS) $(ROOT)/lsasafe.h $(ROOT)/store.h $(ROOT)/storekeys.h
	$(CXX) $(CXXFLAGS) $(SANITIZE) $(LSA_SOURCES) -o $@

clean:
	rm -f test_verify test_lsa
