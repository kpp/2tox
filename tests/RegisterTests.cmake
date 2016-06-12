
cxx_test(PRETTY_NAME "core::network" BIN_NAME "test_network" SOURCES "toxcore/test_network.cpp" LIBS toxcore)
cxx_test(PRETTY_NAME "core::crypto::core" BIN_NAME "test_crypto_core" SOURCES "toxcore/test_crypto_core.cpp" LIBS toxcore)
cxx_test(PRETTY_NAME "encryptsave" BIN_NAME "test_encryptsave" SOURCES "toxencryptsave/test_encryptsave.cpp" LIBS toxencryptsave)
