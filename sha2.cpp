#include <cryptopp/sha.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>

#include <iostream>
#include <string>

using namespace std;

string sha224(const string message) {
    string hashValue = "";

    CryptoPP::SHA224 sha224;

    CryptoPP::StringSource(message, true, new CryptoPP::HashFilter(sha224, new CryptoPP::HexEncoder(new CryptoPP::StringSink(hashValue))));

    return hashValue;
}

string sha256(const string message) {
    string hashValue = "";

    CryptoPP::SHA256 sha256;

    CryptoPP::StringSource(message, true, new CryptoPP::HashFilter(sha256, new CryptoPP::HexEncoder(new CryptoPP::StringSink(hashValue))));

    return hashValue;
}

string sha384(const string message) {
    string hashValue = "";

    CryptoPP::SHA384 sha384;

    CryptoPP::StringSource(message, true, new CryptoPP::HashFilter(sha384, new CryptoPP::HexEncoder(new CryptoPP::StringSink(hashValue))));

    return hashValue;
}

string sha512(const string message) {
    string hashValue = "";

    CryptoPP::SHA512 sha512;

    CryptoPP::StringSource(message, true, new CryptoPP::HashFilter(sha512, new CryptoPP::HexEncoder(new CryptoPP::StringSink(hashValue))));

    return hashValue;
}

int main(int argc, char const *argv[])
{
    string message = argv[1];

    cout << "Message: " << message << endl << endl;
    cout << "Hash value using SHA224: " << sha224(message) << endl;
    cout << "Hash length: " << sha224(message).length() << " digits long" << endl << endl;

    cout << "Hash value using SHA256: " << sha256(message) << endl;
    cout << "Hash length: " << sha256(message).length() << " digits long" << endl << endl;

    cout << "Hash value using SHA384: " << sha384(message) << endl;
    cout << "Hash length: " << sha384(message).length() << " digits long" << endl << endl;

    cout << "Hash value using SHA512: " << sha512(message) << endl;
    cout << "Hash length: " << sha512(message).length() << " digits long" << endl << endl;

    return 0;
}
