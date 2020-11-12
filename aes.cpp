#include "cryptopp/pch.h"
#include <iostream>

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include <cstdlib>
using std::exit;

#include "cryptopp/cryptlib.h"
using CryptoPP::Exception;

#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;

#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/ccm.h"
using CryptoPP::CBC_Mode;
using CryptoPP::CFB_Mode;
using CryptoPP::CTR_Mode;
using CryptoPP::ECB_Mode;
using CryptoPP::OFB_Mode;

#include "assert.h"

string AesCBCMode(string plaintext) {
	AutoSeededRandomPool prng;

	byte key[AES::DEFAULT_KEYLENGTH];
	prng.GenerateBlock(key, sizeof(key));

	byte iv[AES::BLOCKSIZE];
	prng.GenerateBlock(iv, sizeof(iv));

	string encrypt, encoded, decrypt;

	CBC_Mode< AES >::Encryption e;
	e.SetKeyWithIV(key, sizeof(key), iv);

	//The StreamTransformationFilter adds padding.
	StringSource (plaintext, true,
		new StreamTransformationFilter(e,
			new StringSink(encrypt)
		) //StreamTransformationFilter
	); //StringSource

	encoded.clear();
	StringSource (encrypt, true,
		new HexEncoder(
			new StringSink(encoded)
		) //HexEncoder
	); //StringSource
	
	return encoded;
}

string AesCFBMode(string plaintext) {
	AutoSeededRandomPool prng;

	byte key[AES::DEFAULT_KEYLENGTH];
	prng.GenerateBlock(key, sizeof(key));

	byte iv[AES::BLOCKSIZE];
	prng.GenerateBlock(iv, sizeof(iv));

	string encrypt, encoded, decrypt;

	CFB_Mode< AES >::Encryption e;
	e.SetKeyWithIV(key, sizeof(key), iv);

	//The StreamTransformationFilter adds padding.
	StringSource (plaintext, true,
		new StreamTransformationFilter(e,
			new StringSink(encrypt)
		) //StreamTransformationFilter
	); //StringSource

	encoded.clear();
	StringSource (encrypt, true,
		new HexEncoder(
			new StringSink(encoded)
		) //HexEncoder
	); //StringSource

	return encoded;
}

string AesCTRMode(string plaintext) {
	AutoSeededRandomPool prng;

	byte key[AES::DEFAULT_KEYLENGTH];
	prng.GenerateBlock(key, sizeof(key));

	byte iv[AES::BLOCKSIZE];
	prng.GenerateBlock(iv, sizeof(iv));

	string encrypt, encoded, decrypt;

	CTR_Mode< AES >::Encryption e;
	e.SetKeyWithIV(key, sizeof(key), iv);

	//The StreamTransformationFilter adds padding.
	StringSource (plaintext, true,
		new StreamTransformationFilter(e,
			new StringSink(encrypt)
		) //StreamTransformationFilter
	); //StringSource

	encoded.clear();
	StringSource (encrypt, true,
		new HexEncoder(
			new StringSink(encoded)
		) //HexEncoder
	); //StringSource

	return encoded;
}

string AesECBMode(string plaintext) {
	AutoSeededRandomPool prng;

	byte key[AES::DEFAULT_KEYLENGTH];
	prng.GenerateBlock(key, sizeof(key));

	string encrypt, encoded, decrypt;

	ECB_Mode< AES >::Encryption e;
	e.SetKey(key, sizeof(key));

	//The StreamTransformationFilter adds padding.
	StringSource (plaintext, true,
		new StreamTransformationFilter(e,
			new StringSink(encrypt)
		) //StreamTransformationFilter
	); //StringSource

	encoded.clear();
	StringSource (encrypt, true,
		new HexEncoder(
			new StringSink(encoded)
		) //HexEncoder
	); //StringSource

	return encoded;
}

string AesOFBMode(string plaintext) {
	AutoSeededRandomPool prng;

	byte key[AES::DEFAULT_KEYLENGTH];
	prng.GenerateBlock(key, sizeof(key));

	byte iv[AES::BLOCKSIZE];
	prng.GenerateBlock(iv, sizeof(iv));

	string encrypt, encoded, decrypt;

	OFB_Mode< AES >::Encryption e;
	e.SetKeyWithIV(key, sizeof(key), iv);

	//The StreamTransformationFilter adds padding.
	StringSource (plaintext, true,
		new StreamTransformationFilter(e,
			new StringSink(encrypt)
		) //StreamTransformationFilter
	); //StringSource

	encoded.clear();
	StringSource (encrypt, true,
		new HexEncoder(
			new StringSink(encoded)
		) //HexEncoder
	); //StringSource

	return encoded;
}

int main(int argc, char* argv[]) {

	string message = argv[1];
	
	cout << "Plain Text: " << message << endl;

	cout << "Encrypted Text by AES CBC mode : " << AesCBCMode(message) << endl;
	cout << "Encrypted Text by AES CFB mode : " << AesCFBMode(message) << endl;
	cout << "Encrypted Text by AES CTR mode : " << AesCTRMode(message) << endl;
	cout << "Encrypted Text by AES ECB mode : " << AesECBMode(message) << endl;
	cout << "Encrypted Text by AES OFB mode : " << AesOFBMode(message) << endl << endl;

	return 0;
}
