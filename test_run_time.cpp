#include <cryptopp/sha.h>
#include <cryptopp/sha3.h>
#include "cryptopp/cryptlib.h"
#include "cryptopp/secblock.h"
#include "cryptopp/osrng.h"
#include "cryptopp/dsa.h"
#include "cryptopp/eccrypto.h"
#include "cryptopp/oids.h"
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include "cryptopp/aes.h"
#include "cryptopp/ccm.h"

#include <iostream>
#include <string>
#include <ctime>
#include <chrono>
#include <unistd.h>

using namespace std;

string sha1(const string message) {         // SHA1
    string hashValue = "";

    CryptoPP::SHA1 sha1;

    CryptoPP::StringSource(message, true, new CryptoPP::HashFilter(sha1, new CryptoPP::HexEncoder(new CryptoPP::StringSink(hashValue))));

    return hashValue;
}

string sha224(const string message) {       // SHA2-224
    string hashValue = "";

    CryptoPP::SHA224 sha224;

    CryptoPP::StringSource(message, true, new CryptoPP::HashFilter(sha224, new CryptoPP::HexEncoder(new CryptoPP::StringSink(hashValue))));

    return hashValue;
}

string sha256(const string message) {       // SHA2-256
    string hashValue = "";

    CryptoPP::SHA256 sha256;

    CryptoPP::StringSource(message, true, new CryptoPP::HashFilter(sha256, new CryptoPP::HexEncoder(new CryptoPP::StringSink(hashValue))));

    return hashValue;
}

string sha384(const string message) {       // SHA2-384
    string hashValue = "";

    CryptoPP::SHA384 sha384;

    CryptoPP::StringSource(message, true, new CryptoPP::HashFilter(sha384, new CryptoPP::HexEncoder(new CryptoPP::StringSink(hashValue))));

    return hashValue;
}

string sha512(const string message) {       // SHA2-512
    string hashValue = "";

    CryptoPP::SHA512 sha512;

    CryptoPP::StringSource(message, true, new CryptoPP::HashFilter(sha512, new CryptoPP::HexEncoder(new CryptoPP::StringSink(hashValue))));

    return hashValue;
}

string sha3_224(const string message) {     // SHA3-224
    string hashValue = "";

    CryptoPP::SHA3_224 sha3_224;

    CryptoPP::StringSource(message, true, new CryptoPP::HashFilter(sha3_224, new CryptoPP::HexEncoder(new CryptoPP::StringSink(hashValue))));

    return hashValue;
}

string sha3_256(const string message) {     // SHA3-256
    string hashValue = "";

    CryptoPP::SHA3_256 sha3_256;

    CryptoPP::StringSource(message, true, new CryptoPP::HashFilter(sha3_256, new CryptoPP::HexEncoder(new CryptoPP::StringSink(hashValue))));

    return hashValue;
}

string sha3_384(const string message) {     // SHA3-384
    string hashValue = "";

    CryptoPP::SHA3_384 sha3_384;

    CryptoPP::StringSource(message, true, new CryptoPP::HashFilter(sha3_384, new CryptoPP::HexEncoder(new CryptoPP::StringSink(hashValue))));

    return hashValue;
}

string sha3_512(const string message) {     // SHA3-512
    string hashValue = "";

    CryptoPP::SHA3_512 sha3_512;

    CryptoPP::StringSource(message, true, new CryptoPP::HashFilter(sha3_512, new CryptoPP::HexEncoder(new CryptoPP::StringSink(hashValue))));

    return hashValue;
}

string AesCBCMode(string plaintext) {
	CryptoPP::AutoSeededRandomPool prng;

	byte key[CryptoPP::AES::DEFAULT_KEYLENGTH];
	prng.GenerateBlock(key, sizeof(key));

	byte iv[CryptoPP::AES::BLOCKSIZE];
	prng.GenerateBlock(iv, sizeof(iv));

	string encrypt, encoded, decrypt;

	CryptoPP::CBC_Mode< CryptoPP::AES >::Encryption e;
	e.SetKeyWithIV(key, sizeof(key), iv);

	//The StreamTransformationFilter adds padding.
	CryptoPP::StringSource (plaintext, true,
		new CryptoPP::StreamTransformationFilter(e,
			new CryptoPP::StringSink(encrypt)
		) //StreamTransformationFilter
	); //StringSource

	encoded.clear();
	CryptoPP::StringSource (encrypt, true,
		new CryptoPP::HexEncoder(
			new CryptoPP::StringSink(encoded)
		) //HexEncoder
	); //StringSource
	
	return encoded;
}

string AesCFBMode(string plaintext) {
	CryptoPP::AutoSeededRandomPool prng;

	byte key[CryptoPP::AES::DEFAULT_KEYLENGTH];
	prng.GenerateBlock(key, sizeof(key));

	byte iv[CryptoPP::AES::BLOCKSIZE];
	prng.GenerateBlock(iv, sizeof(iv));

	string encrypt, encoded, decrypt;

	CryptoPP::CFB_Mode< CryptoPP::AES >::Encryption e;
	e.SetKeyWithIV(key, sizeof(key), iv);

	//The StreamTransformationFilter adds padding.
	CryptoPP::StringSource (plaintext, true,
		new CryptoPP::StreamTransformationFilter(e,
			new CryptoPP::StringSink(encrypt)
		) //StreamTransformationFilter
	); //StringSource

	encoded.clear();
	CryptoPP::StringSource (encrypt, true,
		new CryptoPP::HexEncoder(
			new CryptoPP::StringSink(encoded)
		) //HexEncoder
	); //StringSource

	return encoded;
}

string AesCTRMode(string plaintext) {
	CryptoPP::AutoSeededRandomPool prng;

	byte key[CryptoPP::AES::DEFAULT_KEYLENGTH];
	prng.GenerateBlock(key, sizeof(key));

	byte iv[CryptoPP::AES::BLOCKSIZE];
	prng.GenerateBlock(iv, sizeof(iv));

	string encrypt, encoded, decrypt;

	CryptoPP::CTR_Mode< CryptoPP::AES >::Encryption e;
	e.SetKeyWithIV(key, sizeof(key), iv);

	//The StreamTransformationFilter adds padding.
	CryptoPP::StringSource (plaintext, true,
		new CryptoPP::StreamTransformationFilter(e,
			new CryptoPP::StringSink(encrypt)
		) //StreamTransformationFilter
	); //StringSource

	encoded.clear();
	CryptoPP::StringSource (encrypt, true,
		new CryptoPP::HexEncoder(
			new CryptoPP::StringSink(encoded)
		) //HexEncoder
	); //StringSource

	return encoded;
}

string AesECBMode(string plaintext) {
	CryptoPP::AutoSeededRandomPool prng;

	byte key[CryptoPP::AES::DEFAULT_KEYLENGTH];
	prng.GenerateBlock(key, sizeof(key));

	string encrypt, encoded, decrypt;

	CryptoPP::ECB_Mode< CryptoPP::AES >::Encryption e;
	e.SetKey(key, sizeof(key));

	//The StreamTransformationFilter adds padding.
	CryptoPP::StringSource (plaintext, true,
		new CryptoPP::StreamTransformationFilter(e,
			new CryptoPP::StringSink(encrypt)
		) //StreamTransformationFilter
	); //StringSource

	encoded.clear();
	CryptoPP::StringSource (encrypt, true,
		new CryptoPP::HexEncoder(
			new CryptoPP::StringSink(encoded)
		) //HexEncoder
	); //StringSource

	return encoded;
}

string AesOFBMode(string plaintext) {
	CryptoPP::AutoSeededRandomPool prng;

	byte key[CryptoPP::AES::DEFAULT_KEYLENGTH];
	prng.GenerateBlock(key, sizeof(key));

	byte iv[CryptoPP::AES::BLOCKSIZE];
	prng.GenerateBlock(iv, sizeof(iv));

	string encrypt, encoded, decrypt;

	CryptoPP::OFB_Mode< CryptoPP::AES >::Encryption e;
	e.SetKeyWithIV(key, sizeof(key), iv);

	//The StreamTransformationFilter adds padding.
	CryptoPP::StringSource (plaintext, true,
		new CryptoPP::StreamTransformationFilter(e,
			new CryptoPP::StringSink(encrypt)
		) //StreamTransformationFilter
	); //StringSource

	encoded.clear();
	CryptoPP::StringSource (encrypt, true,
		new CryptoPP::HexEncoder(
			new CryptoPP::StringSink(encoded)
		) //HexEncoder
	); //StringSource

	return encoded;
}


string dsa2(string message) {               // DSA2
    CryptoPP::AutoSeededRandomPool prng;

    CryptoPP::DSA::PrivateKey privateKey;
    privateKey.Initialize(prng, 2048);
    
    message.resize(CryptoPP::SHA224::DIGESTSIZE);

    ::memset(&message[0], 0xAA, message.size());

    CryptoPP::DSA::Signer signer(privateKey);
    string signature;

    CryptoPP::StringSource ss(message, true,
                        new CryptoPP::SignerFilter(prng, signer,
                            new CryptoPP::HexEncoder(new CryptoPP::StringSink(signature))
                        ) // SignerFilter
                    ); // StringSource

    return signature;
}

string ecdsa(string message) {              // ECDSA
    CryptoPP::AutoSeededRandomPool prng;

    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey privateKey;
    privateKey.Initialize(prng, CryptoPP::ASN1::secp256r1());

    
    message.resize(CryptoPP::SHA256::DIGESTSIZE);
    ::memset(&message[0], 0xAA, message.size());

    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256 >::Signer signer(privateKey);
    string signature;

    CryptoPP::StringSource ss(message, true,
                        new CryptoPP::SignerFilter(prng, signer,
                            new CryptoPP::HexEncoder(new CryptoPP::StringSink(signature))
                        ) // SignerFilter
                    ); // StringSource

    return signature;
}

double testSHA1(string string) {
    double total_execute_time = 0;

    for (int i=0; i < 1000; i++) {
        auto start_time = chrono::high_resolution_clock::now();
        sha1(string);
        auto end_time = chrono::high_resolution_clock::now();

        total_execute_time += std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time).count();        
    }

    return total_execute_time/1000;
}

double testSHA2_224(string string) {
    double total_execute_time = 0;

    for (int i=0; i < 1000; i++) {
        auto start_time = chrono::high_resolution_clock::now();
        sha224(string);
        auto end_time = chrono::high_resolution_clock::now();

        total_execute_time += std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time).count();        
    }

    return total_execute_time/1000;
}

double testSHA2_256(string string) {
    double total_execute_time = 0;

    for (int i=0; i < 1000; i++) {
        auto start_time = chrono::high_resolution_clock::now();
        sha256(string);
        auto end_time = chrono::high_resolution_clock::now();

        total_execute_time += std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time).count();        
    }

    return total_execute_time/1000;
}

double testSHA2_384(string string) {
    double total_execute_time = 0;

    for (int i=0; i < 1000; i++) {
        auto start_time = chrono::high_resolution_clock::now();
        sha384(string);
        auto end_time = chrono::high_resolution_clock::now();

        total_execute_time += std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time).count();        
    }

    return total_execute_time/1000;
}

double testSHA2_512(string string) {
    double total_execute_time = 0;

    for (int i=0; i < 1000; i++) {
        auto start_time = chrono::high_resolution_clock::now();
        sha512(string);
        auto end_time = chrono::high_resolution_clock::now();

        total_execute_time += std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time).count();        
    }

    return total_execute_time/1000;
}

double testSHA3_224(string string) {
    double total_execute_time = 0;

    for (int i=0; i < 1000; i++) {
        auto start_time = chrono::high_resolution_clock::now();
        sha3_224(string);
        auto end_time = chrono::high_resolution_clock::now();

        total_execute_time += std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time).count();        
    }

    return total_execute_time/1000;
}

double testSHA3_256(string string) {
    double total_execute_time = 0;

    for (int i=0; i < 1000; i++) {
        auto start_time = chrono::high_resolution_clock::now();
        sha3_256(string);
        auto end_time = chrono::high_resolution_clock::now();

        total_execute_time += std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time).count();        
    }

    return total_execute_time/1000;
}

double testSHA3_384(string string) {
    double total_execute_time = 0;

    for (int i=0; i < 1000; i++) {
        auto start_time = chrono::high_resolution_clock::now();
        sha3_384(string);
        auto end_time = chrono::high_resolution_clock::now();

        total_execute_time += std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time).count();        
    }

    return total_execute_time/1000;
}

double testSHA3_512(string string) {
    double total_execute_time = 0;

    for (int i=0; i < 1000; i++) {
        auto start_time = chrono::high_resolution_clock::now();
        sha3_512(string);
        auto end_time = chrono::high_resolution_clock::now();

        total_execute_time += std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time).count();        
    }

    return total_execute_time/1000;
}

double testAesCBCMode(string string) {
    double total_execute_time = 0;

    for (int i=0; i < 1000; i++) {
        auto start_time = chrono::high_resolution_clock::now();
        AesCBCMode(string);
        auto end_time = chrono::high_resolution_clock::now();

        total_execute_time += std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time).count();        
    }

    return total_execute_time/1000;
}

double testAesCFBMode(string string) {
    double total_execute_time = 0;

    for (int i=0; i < 1000; i++) {
        auto start_time = chrono::high_resolution_clock::now();
        AesCFBMode(string);
        auto end_time = chrono::high_resolution_clock::now();

        total_execute_time += std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time).count();        
    }

    return total_execute_time/1000;
}

double testAesCTRMode(string string) {
    double total_execute_time = 0;

    for (int i=0; i < 1000; i++) {
        auto start_time = chrono::high_resolution_clock::now();
        AesCTRMode(string);
        auto end_time = chrono::high_resolution_clock::now();

        total_execute_time += std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time).count();        
    }

    return total_execute_time/1000;
}

double testAesECBMode(string string) {
    double total_execute_time = 0;

    for (int i=0; i < 1000; i++) {
        auto start_time = chrono::high_resolution_clock::now();
        AesECBMode(string);
        auto end_time = chrono::high_resolution_clock::now();

        total_execute_time += std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time).count();        
    }

    return total_execute_time/1000;
}

double testAesOFBMode(string string) {
    double total_execute_time = 0;

    for (int i=0; i < 1000; i++) {
        auto start_time = chrono::high_resolution_clock::now();
        AesOFBMode(string);
        auto end_time = chrono::high_resolution_clock::now();

        total_execute_time += std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time).count();        
    }

    return total_execute_time/1000;
}

double testDSA2(string string) {
    double total_execute_time = 0;

    for (int i=0; i < 1000; i++) {
        auto start_time = chrono::high_resolution_clock::now();
        dsa2(string);
        auto end_time = chrono::high_resolution_clock::now();

        total_execute_time += std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();        
    }

    return total_execute_time/1000;
}

double testECDSA(string string) {
    double total_execute_time = 0;

    for (int i=0; i < 1000; i++) {
        auto start_time = chrono::high_resolution_clock::now();
        ecdsa(string);
        auto end_time = chrono::high_resolution_clock::now();

        total_execute_time += std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time).count();        
    }

    return total_execute_time/1000;
}

int main(int argc, char const *argv[]) {

    string string256 = "5PAodO5XNLTW30qkTtBlpEkWGc9GaDY6bVYDgDyraXR7Z11IosEBgNDke59Lf1Nk2vwODUvv4s4jwUk88PrWSKzPAFr8ZR38FI4SFQtD3uYsR65SDUHBWPPrmfmpBOpKvPsxaOypl3wHZe6mKE8APYXuFTVFF1nINID93x8G5M84x4pZy0pDdpBfnE8rmdRarGb5U9TfoeBMwtdzmG8T0S8NprHP8HIfyW7sbs8PeZJY22L3duyMN0S4ZDHJhpwb";
    string string512 = "ZzKT5Q5lCMHxT2M8NtcpUZZJnVfAKePTEbPbXAfp23JaSNmXo5YfRTbdfK5pF5kbepmfS4skLemW8T2CePo4f5sFbCt2g2ElIUKwh3PYlYxlL83ODnTRLFWKOo4YgKZMknknQoIC4o83FCMvdPyzuE1OQxVihqkCmWMc9Pxz0eZGkvDLrNjErwmoAyt1u5SEjI4ceHtWkNW73nvLTEIXpOHLY47Bpe8IPXg17Gc1L2IwAohD6KlWniOsPc5F3gY7joPcdhMb54HFwC3iNR6BmhDoo4efmhpGXMBfdICrPXSjDLVTtlJO9j9TdESHoAgMwCGlLk3EadbE86D0dOHqhlfC4GL6bm5L6R2NVEXPRADe1pT2H8QmjgMNngPviplEW84QSJxGAGvF2qeY4TMSdn4Bdx9dMjwNQ0c0epqwOeYqMTKKS24Da1qZHoRnEuWHuhYKuhkVhwg5Kqa7kakgdxSvAx58k80qkn3FrUMB588jSwp0gyVvUnBCnZlGys5l";
    string string1024 = "8kuD9auoLuXLwBOtffwnwTtyescD8S7rIYjhijcGCON9BjcPeGQY1LJpCBPhVCXM7q65ZVbJuoi29U7LVxvSIWhj2tBMMzag66ntJpWmHYtwFQl9JgKnVzGJhMb3klyAZzHgO7gy2TrbYF9x8hfKlKmrvPEPn8Sh2MKDI4TeegWEEdAKYT2nuG13P9IHHpL8BC0qAkYWnfyzmWYa5au7szHhcQeEevfaz7qMoNM1F0G9BCtyxeWiQuiUgxSiBJoE5pTJKRaoB1dJnTyBJPT4q5LZYhYxMa4fnCA55dOMmsKyJwrPLoaAjBBMbpBO3zSDh8FHXpmZeesfxl2yH7EQYSEEyASGYzNIixSmE9FS9dNiqIeW3Oj7DtUZ2syzKqPytUhAdhhmFCq3ltn88EYG5fC9z1PctEgEO8GRWflB2HWVf0ji73uzvblq8mHLe1uMblaxcUVCAcEGXL0Z5DawDQ4vIo8Z5lCcWblWuWgYOXjx4RJNkZBLQTFiHkbUi09jbEcgfmuzOI1aNXKx2Y0tqYvkQQ3JfNgYm5XKCFLALZu7gnKxE4P9NV3ybcZpNcynJ3dfJWpGzPyop98Td03fVrWAUe13RvRLE5XjtMbGjkrHLPdlK9Gcqrba3UA6GPwFLvOVK8ipXusWoZKrjOSiErPIt5nl5Jomld9Clp3dA3eLdRZ8s6pXC8t1aC97Zs9bbVTiWgbIb5VRAI9bcbWeUVjgFC2OrOjbwS7WkokgdFaVxG0VClWoAqqZZ5d5wdbXjdUddOp8YSxah2DKbirElVPCAZRjwaf5wmKCSObTPeNjayVUQM516KLizjpjMuENcvfoEFwREQNNUBeEYqlsagbfGPfYZjfZbW0S46bclKetcTFW58I1ZAOZRoJoZ7IYurTxT92PwKtChYlZtLA8oGbwV7GVbViXcAlwb9YSZTo6bfWGbyq8QxhyHJoZchqJQe3vyDTu0WJyq6ogA2zg7oSKqU5jOgzflQbQY12n1b67oZSr49KirSuXdNXK6KDc";
    string string2048 = "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";
    string string4096 = "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";


    cout << "Average execution time on Sha1 funtion with 256 bits string length: " << testSHA1(string256) << " microseconds" << endl;
    cout << "Average execution time on Sha1 funtion with 512 bits string length: " << testSHA1(string512) << " microseconds" << endl;
    cout << "Average execution time on Sha1 funtion with 1024 bits string length: " << testSHA1(string1024) << " microseconds" << endl;
    cout << "Average execution time on Sha1 funtion with 2048 bits string length: " << testSHA1(string2048) << " microseconds" << endl;
    cout << "Average execution time on Sha1 funtion with 4096 bits string length: " << testSHA1(string4096) << " microseconds" << endl << endl;

    cout << "Average execution time on Sha2-224 funtion with 256 bits string length: " << testSHA2_224(string256) << " microseconds" << endl;
    cout << "Average execution time on Sha2-224 funtion with 512 bits string length: " << testSHA2_224(string512) << " microseconds" << endl;
    cout << "Average execution time on Sha2-224 funtion with 1024 bits string length: " << testSHA2_224(string1024) << " microseconds" << endl;
    cout << "Average execution time on Sha2-224 funtion with 2048 bits string length: " << testSHA2_224(string2048) << " microseconds" << endl;
    cout << "Average execution time on Sha2-224 funtion with 4096 bits string length: " << testSHA2_224(string4096) << " microseconds" << endl << endl;

    cout << "Average execution time on Sha2-256 funtion with 256 bits string length: " << testSHA2_256(string256) << " microseconds" << endl;
    cout << "Average execution time on Sha2-256 funtion with 512 bits string length: " << testSHA2_256(string512) << " microseconds" << endl;
    cout << "Average execution time on Sha2-256 funtion with 1024 bits string length: " << testSHA2_256(string1024) << " microseconds" << endl;
    cout << "Average execution time on Sha2-256 funtion with 2048 bits string length: " << testSHA2_256(string2048) << " microseconds" << endl;
    cout << "Average execution time on Sha2-256 funtion with 4096 bits string length: " << testSHA2_256(string4096) << " microseconds" << endl << endl;

    cout << "Average execution time on Sha2-384 funtion with 256 bits string length: " << testSHA2_384(string256) << " microseconds" << endl;
    cout << "Average execution time on Sha2-384 funtion with 512 bits string length: " << testSHA2_384(string512) << " microseconds" << endl;
    cout << "Average execution time on Sha2-384 funtion with 1024 bits string length: " << testSHA2_384(string1024) << " microseconds" << endl;
    cout << "Average execution time on Sha2-384 funtion with 2048 bits string length: " << testSHA2_384(string2048) << " microseconds" << endl;
    cout << "Average execution time on Sha2-384 funtion with 4096 bits string length: " << testSHA2_384(string4096) << " microseconds" << endl << endl;

    cout << "Average execution time on Sha2-512 funtion with 256 bits string length: " << testSHA2_512(string256) << " microseconds" << endl;
    cout << "Average execution time on Sha2-512 funtion with 512 bits string length: " << testSHA2_512(string512) << " microseconds" << endl;
    cout << "Average execution time on Sha2-512 funtion with 1024 bits string length: " << testSHA2_512(string1024) << " microseconds" << endl;
    cout << "Average execution time on Sha2-512 funtion with 2048 bits string length: " << testSHA2_512(string2048) << " microseconds" << endl;
    cout << "Average execution time on Sha2-512 funtion with 4096 bits string length: " << testSHA2_512(string4096) << " microseconds" << endl << endl;

    cout << "Average execution time on Sha3-224 funtion with 256 bits string length: " << testSHA3_224(string256) << " microseconds" << endl;
    cout << "Average execution time on Sha3-224 funtion with 512 bits string length: " << testSHA3_224(string512) << " microseconds" << endl;
    cout << "Average execution time on Sha3-224 funtion with 1024 bits string length: " << testSHA3_224(string1024) << " microseconds" << endl;
    cout << "Average execution time on Sha3-224 funtion with 2048 bits string length: " << testSHA3_224(string2048) << " microseconds" << endl;
    cout << "Average execution time on Sha3-224 funtion with 4096 bits string length: " << testSHA3_224(string4096) << " microseconds" << endl << endl;

    cout << "Average execution time on Sha3-256 funtion with 256 bits string length: " << testSHA3_256(string256) << " microseconds" << endl;
    cout << "Average execution time on Sha3-256 funtion with 512 bits string length: " << testSHA3_256(string512) << " microseconds" << endl;
    cout << "Average execution time on Sha3-256 funtion with 1024 bits string length: " << testSHA3_256(string1024) << " microseconds" << endl;
    cout << "Average execution time on Sha3-256 funtion with 2048 bits string length: " << testSHA3_256(string2048) << " microseconds" << endl;
    cout << "Average execution time on Sha3-256 funtion with 4096 bits string length: " << testSHA3_256(string4096) << " microseconds" << endl << endl;

    cout << "Average execution time on Sha3-384 funtion with 256 bits string length: " << testSHA3_384(string256) << " microseconds" << endl;
    cout << "Average execution time on Sha3-384 funtion with 512 bits string length: " << testSHA3_384(string512) << " microseconds" << endl;
    cout << "Average execution time on Sha3-384 funtion with 1024 bits string length: " << testSHA3_384(string1024) << " microseconds" << endl;
    cout << "Average execution time on Sha3-384 funtion with 2048 bits string length: " << testSHA3_384(string2048) << " microseconds" << endl;
    cout << "Average execution time on Sha3-384 funtion with 4096 bits string length: " << testSHA3_384(string4096) << " microseconds" << endl << endl;

    cout << "Average execution time on Sha3-512 funtion with 256 bits string length: " << testSHA3_512(string256) << " microseconds" << endl;
    cout << "Average execution time on Sha3-512 funtion with 512 bits string length: " << testSHA3_512(string512) << " microseconds" << endl;
    cout << "Average execution time on Sha3-512 funtion with 1024 bits string length: " << testSHA3_512(string1024) << " microseconds" << endl;
    cout << "Average execution time on Sha3-512 funtion with 2048 bits string length: " << testSHA3_512(string2048) << " microseconds" << endl;
    cout << "Average execution time on Sha3-512 funtion with 4096 bits string length: " << testSHA3_512(string4096) << " microseconds" << endl << endl;

    cout << "Average execution time on AES CBC Mode funtion with 256 bits string length: " << testAesCBCMode(string256) << " microseconds" << endl;
    cout << "Average execution time on AES CBC Mode funtion with 512 bits string length: " << testAesCBCMode(string512) << " microseconds" << endl;
    cout << "Average execution time on AES CBC Mode funtion with 1024 bits string length: " << testAesCBCMode(string1024) << " microseconds" << endl;
    cout << "Average execution time on AES CBC Mode funtion with 2049 bits string length: " << testAesCBCMode(string2048) << " microseconds" << endl;
    cout << "Average execution time on AES CBC Mode funtion with 4096 bits string length: " << testAesCBCMode(string4096) << " microseconds" << endl << endl;

    cout << "Average execution time on AES CFB Mode funtion with 256 bits string length: " << testAesCFBMode(string256) << " microseconds" << endl;
    cout << "Average execution time on AES CFB Mode funtion with 512 bits string length: " << testAesCFBMode(string512) << " microseconds" << endl;
    cout << "Average execution time on AES CFB Mode funtion with 1024 bits string length: " << testAesCFBMode(string1024) << " microseconds" << endl;
    cout << "Average execution time on AES CFB Mode funtion with 2049 bits string length: " << testAesCFBMode(string2048) << " microseconds" << endl;
    cout << "Average execution time on AES CFB Mode funtion with 4096 bits string length: " << testAesCFBMode(string4096) << " microseconds" << endl << endl;

    cout << "Average execution time on AES CTR Mode funtion with 256 bits string length: " << testAesCTRMode(string256) << " microseconds" << endl;
    cout << "Average execution time on AES CTR Mode funtion with 512 bits string length: " << testAesCTRMode(string512) << " microseconds" << endl;
    cout << "Average execution time on AES CTR Mode funtion with 1024 bits string length: " << testAesCTRMode(string1024) << " microseconds" << endl;
    cout << "Average execution time on AES CTR Mode funtion with 2049 bits string length: " << testAesCTRMode(string2048) << " microseconds" << endl;
    cout << "Average execution time on AES CTR Mode funtion with 4096 bits string length: " << testAesCTRMode(string4096) << " microseconds" << endl << endl;

    cout << "Average execution time on AES ECB Mode funtion with 256 bits string length: " << testAesECBMode(string256) << " microseconds" << endl;
    cout << "Average execution time on AES ECB Mode funtion with 512 bits string length: " << testAesECBMode(string512) << " microseconds" << endl;
    cout << "Average execution time on AES ECB Mode funtion with 1024 bits string length: " << testAesECBMode(string1024) << " microseconds" << endl;
    cout << "Average execution time on AES ECB Mode funtion with 2049 bits string length: " << testAesECBMode(string2048) << " microseconds" << endl;
    cout << "Average execution time on AES ECB Mode funtion with 4096 bits string length: " << testAesECBMode(string4096) << " microseconds" << endl << endl;

    cout << "Average execution time on AES OFB Mode funtion with 256 bits string length: " << testAesOFBMode(string256) << " microseconds" << endl;
    cout << "Average execution time on AES OFB Mode funtion with 512 bits string length: " << testAesOFBMode(string512) << " microseconds" << endl;
    cout << "Average execution time on AES OFB Mode funtion with 1024 bits string length: " << testAesOFBMode(string1024) << " microseconds" << endl;
    cout << "Average execution time on AES OFB Mode funtion with 2049 bits string length: " << testAesOFBMode(string2048) << " microseconds" << endl;
    cout << "Average execution time on AES OFB Mode funtion with 4096 bits string length: " << testAesOFBMode(string4096) << " microseconds" << endl << endl;

    cout << "Average execution time on DSA2 funtion with 256 bits string length: " << testDSA2(string256) << " milliseconds" << endl;
    cout << "Average execution time on DSA2 funtion with 512 bits string length: " << testDSA2(string512) << " milliseconds" << endl;
    cout << "Average execution time on DSA2 funtion with 1024 bits string length: " << testDSA2(string1024) << " milliseconds" << endl;
    cout << "Average execution time on DSA2 funtion with 2048 bits string length: " << testDSA2(string2048) << " milliseconds" << endl;
    cout << "Average execution time on DSA2 funtion with 4096 bits string length: " << testDSA2(string4096) << " milliseconds" << endl << endl;

    cout << "Average execution time on ECDSA funtion with 256 bits string length: " << testECDSA(string256) << " microseconds" << endl;
    cout << "Average execution time on ECDSA funtion with 512 bits string length: " << testECDSA(string512) << " microseconds" << endl;
    cout << "Average execution time on ECDSA funtion with 1024 bits string length: " << testECDSA(string1024) << " microseconds" << endl;
    cout << "Average execution time on ECDSA funtion with 2048 bits string length: " << testECDSA(string2048) << " microseconds" << endl;
    cout << "Average execution time on ECDSA funtion with 4096 bits string length: " << testECDSA(string4096) << " microseconds" << endl << endl;

    return 0;
}
