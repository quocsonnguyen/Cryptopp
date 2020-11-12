#include <cryptopp/sha3.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>

#include <iostream>
#include <string>

using namespace std;

string sha3_224(const string message) {
    string hashValue = "";

    CryptoPP::SHA3_224 sha3_224;

    CryptoPP::StringSource(message, true, new CryptoPP::HashFilter(sha3_224, new CryptoPP::HexEncoder(new CryptoPP::StringSink(hashValue))));

    return hashValue;
}

string sha3_256(const string message) {
    string hashValue = "";

    CryptoPP::SHA3_256 sha3_256;

    CryptoPP::StringSource(message, true, new CryptoPP::HashFilter(sha3_256, new CryptoPP::HexEncoder(new CryptoPP::StringSink(hashValue))));

    return hashValue;
}

string sha3_384(const string message) {
    string hashValue = "";

    CryptoPP::SHA3_384 sha3_384;

    CryptoPP::StringSource(message, true, new CryptoPP::HashFilter(sha3_384, new CryptoPP::HexEncoder(new CryptoPP::StringSink(hashValue))));

    return hashValue;
}

string sha3_512(const string message) {
    string hashValue = "";

    CryptoPP::SHA3_512 sha3_512;

    CryptoPP::StringSource(message, true, new CryptoPP::HashFilter(sha3_512, new CryptoPP::HexEncoder(new CryptoPP::StringSink(hashValue))));

    return hashValue;
}

int main(int argc, char const *argv[])
{
    string message = argv[1];

    cout << "Message: " << message << endl << endl;

    cout << "Hash value using SHA3_224: " << sha3_224(message) << endl;
    cout << "Hash length: " << sha3_224(message).length() << " digits long" << endl << endl;

    cout << "Hash value using SHA3_256: " << sha3_256(message) << endl;
    cout << "Hash length: " << sha3_256(message).length() << " digits long" << endl << endl;

    cout << "Hash value using SHA3_384: " << sha3_384(message) << endl;
    cout << "Hash length: " << sha3_384(message).length() << " digits long" << endl << endl;

    cout << "Hash value using SHA3_512: " << sha3_512(message) << endl;
    cout << "Hash length: " << sha3_512(message).length() << " digits long" << endl << endl;

    return 0;
}
