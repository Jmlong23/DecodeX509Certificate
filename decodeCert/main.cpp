#include "decodeX509Cert.h"

int main() {
    X509Reader reader;
    reader.loadFile("icbc_rsa.der");
    reader.compileContent();
    reader.showX509();
    reader.displayResult();
    return 0;
}