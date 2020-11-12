#include "cryptopp/cryptlib.h"
#include "cryptopp/secblock.h"
#include "cryptopp/eccrypto.h"
#include "cryptopp/osrng.h"
#include "cryptopp/oids.h"
#include "cryptopp/hex.h"

#include <iostream>
#include <string>

using namespace CryptoPP;

std::string ecdsa(std::string message) {
    AutoSeededRandomPool prng;

    ECDSA<ECP, SHA256>::PrivateKey privateKey;
    privateKey.Initialize(prng, ASN1::secp256r1());

    
    message.resize(SHA256::DIGESTSIZE);
    ::memset(&message[0], 0xAA, message.size());

    ECDSA<ECP, SHA256 >::Signer signer(privateKey);
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
    std::cout << "Signature: " << ecdsa(message) << std::endl;
    std::cout << "Signature length: " << ecdsa(message).length() << std::endl;

    return 0;
}