#include "cryptopp/cryptlib.h"
#include "cryptopp/secblock.h"
#include "cryptopp/osrng.h"
#include "cryptopp/dsa.h"
#include "cryptopp/hex.h"

#include <iostream>
#include <string>

using namespace CryptoPP;

std::string dsa2(std::string message) {
    AutoSeededRandomPool prng;

    DSA::PrivateKey privateKey;
    privateKey.Initialize(prng, 2048);
    
    message.resize(SHA224::DIGESTSIZE);

    ::memset(&message[0], 0xAA, message.size());

    DSA::Signer signer(privateKey);
    std::string signature;

    StringSource ss(message, true,
                        new SignerFilter(prng, signer,
                            new HexEncoder(new StringSink(signature))
                        ) // SignerFilter
                    ); // StringSource

    return signature;
}

int main(int argc, char* argv[])
{
    std::string message = argv[1];

    std::cout << "Message: " << message << std::endl;
    std::cout << "Signature: " << dsa2(message) << std::endl;
    std::cout << "Signature length: " << dsa2(message).length() << std::endl;

    return 0;
}