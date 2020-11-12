#include <cryptopp/sha.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>

#include <iostream>

#include <string>

using namespace std;

string sha1(const string message) {
    std::string hashValue = "";
    
    CryptoPP::SHA1 sha1;

    // Construct a string sink template
    CryptoPP::StringSink *stringSinkTemplate = new CryptoPP::StringSink(hashValue);

    // Construct a Encoder to encode the string to base 16 
    CryptoPP::HexEncoder *hexEncoder = new CryptoPP::HexEncoder(stringSinkTemplate);

    // Filter the encoded string
    CryptoPP::HashFilter *hashFilter = new CryptoPP::HashFilter(sha1, hexEncoder);

    // Get the hash value of the message
    CryptoPP::StringSource(message, true, hashFilter);

    return hashValue;
}

int main(int argc, char const *argv[])
{
    std::string message = argv[1];

    std::cout << "Message: " << message << std::endl;
    std::cout << "Hash value: " << sha1(message) << std::endl;
    std::cout << "Hash length: " << sha1(message).length() << " digits long" << std::endl << std::endl;

    return 0;
}
