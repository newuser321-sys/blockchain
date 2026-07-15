#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include "sha256.h"
#include <Windows.h>
#include <bcrypt.h>
#include <algorithm>
#include <array>
#include "privatekey.h"
#pragma comment(lib, "bcrypt.lib")
using std::vector, std::cout, std::cin, std::endl, std::string;
using limb = uint64_t;
using limb32 = uint32_t;
using half_thiccy = std::array<uint64_t, 2>;
using thiccy = std::array<uint64_t, 4>;
using fatty = std::array<uint64_t, 8>;

const string n = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
const string P_str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";
thiccy P = { 0xffffffffffffffffULL,0xffffffffffffffffULL,0xffffffffffffffffULL,0xfffffffefffffc2fULL };
const limb zero = 0x0000000000000000;

namespace bytes {
	static uint8_t hexToNibble(char c) {
		if (c >= '0' && c <= '9') return c - '0';
		if (c >= 'a' && c <= 'f') return c - 'a' + 10;
		if (c >= 'A' && c <= 'F') return c - 'A' + 10;
		throw std::runtime_error("invalid hex");
	}

	static thiccy convertEndian(const thiccy& input) {
		thiccy output;
		for (int i = 0; i < 4; i++) {
			output[i] = input[3 - i];
		}
		return output;
	}

	static thiccy hexToBytes(const std::string& hex) {
		thiccy out = {};
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 16; j++) {
				out[i] <<= 4;
				out[i] |= hexToNibble(hex[16 * i + j]);
			}
		}
		return convertEndian(out);
	}

	static string bytesToHex(const thiccy& a) {
		const char* hex = "0123456789abcdef";
		string key;
		key.reserve(64);

		for (int i = 0; i < 4; i++) { // limb = uint64_t
			limb l = a[i];
			for (int j = 15; j >= 0; j--) {
				key.push_back(hex[(l >> (j * 4)) & 0x0F]);
			}
		}
		return key;
	}

	static string byteToHex(const limb& a) {
		const char* hex = "0123456789abcdef";
		string key;
		key.reserve(64);
		for (int j = 15; j >= 0; j--) {
			key.push_back(hex[(a >> (j * 4)) & 0x0F]);
		}

		return key;
	}

	static string bytesToHex(unsigned char a[32]) {
		const char* hex = "0123456789abcdef";
		std::string key;
		key.reserve(64);

		for (int i = 0; i < 32; i++) {
			key.push_back(hex[a[i] >> 4]);   // high nibble
			key.push_back(hex[a[i] & 0x0F]); // low nibble
		}
		return key;
	}
}
using namespace bytes;
static string normalize(std::string s) {
	// remove leading zeros
	s.erase(0, s.find_first_not_of('0'));
	if (s.empty()) s = "0";

	// make lowercase
	std::transform(s.begin(), s.end(), s.begin(), ::tolower);
	return s;
}

static int compareHex(const std::string& a, const std::string& b) {
	string A = normalize(a);
	string B = normalize(b);

	if (A.size() != B.size())
		return A.size() < B.size() ? -1 : 1;

	if (A == B) return 0;
	return A < B ? -1 : 1;
}

static string private_key_rng() {
	unsigned char bytes[32]; // 256 bits

	NTSTATUS status = BCryptGenRandom(
		nullptr,
		bytes,
		sizeof(bytes),
		BCRYPT_USE_SYSTEM_PREFERRED_RNG
	);

	if (status != 0) {
		throw std::runtime_error("BCryptGenRandom failed");
	}

	string key = bytes::bytesToHex(bytes);

	return key;

}
static string create_private_key() {
	while (true) {
		string key = private_key_rng();
		if (key == string(64, '0'))
			continue;
		if (compareHex(key, n) < 0) {
			return key;
		}
	}
}
/////////////////////////// og rng ////////////////////////////////
static string my_private_key_rng() {
	// generate key as binary first
	unsigned char c;
	bool output[256];

	for (int i = 0; i < 256; i++) {
		BCryptGenRandom(nullptr, &c, 1, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
		output[i] = c & 1;
	}
	// convert binary to hex
	string key = "";
	for (int i = 0; i < 256; i++) {
		string temp = std::to_string(output[i]) + std::to_string(output[i + 1]) + std::to_string(output[i + 2]) + std::to_string(output[i + 3]);

		int t = std::stoi(temp, nullptr, 2); // t has any value from 0 - 15

		std::stringstream ss;
		ss << std::hex << t;
		key += ss.str();			// convert t value to hex
		i += 3;
	}
	return key;
}

