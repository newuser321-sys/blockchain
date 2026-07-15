#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include "sha256.h"
#include <Windows.h>
#include <bcrypt.h>
#include <algorithm>
#include <array>
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

	static string bytesToHex(const thiccy &a) {
		const char* hex = "0123456789abcdef";
		string key;
		key.reserve(64);

		for (int i = 0; i < 4; i++) { // limb = uint64_t
			limb l = a[i];
			for (int j = 15; j >= 0; j--) {
				key.push_back(hex[(l >> (j*4)) & 0x0F]);
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

namespace arithmetic {
	static uint8_t addBit(uint8_t a, uint8_t b, uint8_t& carry) {
		uint8_t sum = a ^ b ^ carry;
		carry = (a & b) | (carry & (a ^ b));
		return sum;
	}

	static inline bool cmp(const thiccy& a, const thiccy& b) {
		for (int i = 0; i < 4; i++) {
			if (a[i] == b[i]) {
				continue;
			}
			if (a[i] < b[i]) {
				return 0;
			}
			return 1;
		}
		return 0;
	}

	static inline bool big_cmp(const fatty& a, const fatty& b) {
		for (int i = 0; i < 8; i++) {
			if (a[i] == b[i]) {
				continue;
			}
			if (a[i] < b[i]) {
				return 0;
			}
			return 1;
		}
		return 0;
	}

	static inline limb raw_add(const thiccy& a, const thiccy& b, thiccy& result) { // thiccy = std::array<uint64_t,4>
		uint64_t carry = 0;
		for (int i = 0; i < 4; i++) {
			limb sum = a[i] + b[i] + carry;
			carry = (sum < a[i]) || (carry && (sum == a[i]));
			result[i] = sum;
		}
		return carry;
	}
	// 0110 - 1101 = 1001 
	static inline limb big_raw_add(const fatty& a, const fatty& b, fatty& result) { // thiccy = std::array<uint64_t,4>
		uint64_t carry = 0;
		for (int i = 0; i < 8; i++) {
			limb sum = a[i] + b[i] + carry;
			carry = (sum < a[i]) || (carry && (sum == a[i]));
			result[i] = sum;
		}
		return carry;
	}

	static inline limb raw_sub(const thiccy& a, const thiccy& b, thiccy& result) { // thiccy = std::array<uint64_t,4>
		uint64_t borrow = 0;
		for (int i = 0; i < 4; i++) {
			uint64_t sub = a[i] - b[i] - borrow;
			borrow = (a[i] < (b[i] + borrow));
			result[i] = sub;
		}
		return borrow;
	}

	static inline thiccy add(const thiccy& a, const thiccy& b) {
		thiccy result = {};
		if (raw_add(a, b, result) || cmp(result, P)) {
			raw_sub(result, P, result);
		}
		return result;
	}

	static inline fatty big_add(const fatty& a, const fatty& b) {
		fatty result = {};
		big_raw_add(a, b, result);
		
		return result;
	}

	static inline thiccy sub(const thiccy& a, const thiccy& b) {
		thiccy result = {};
		if (raw_sub(a, b, result)) {
			raw_add(result, P, result);
		}
		return result;
	}

	static inline fatty raw_mul(const thiccy& a, const thiccy& b) {
		fatty product = {};
		std::array<fatty, 4> products = {};
		std::array<half_thiccy, 4> limb_products[4] = {};

		// Ignore these numbers, they are for my understanding
		//   34 12 5 4  2268 504 52,668 472,668
		///     91 4 2  4914 1092
		///		9248 1123 1213
		///		3213 6753 5952
		///	  1 8496 2246 2426
		///   4 6240 5615 6065 0
		///   8 3233 0108 0917 00
		///   8 3233 0108 0917 000
		///   8 3233 0108 0917 0000
		limb carry1 = 0x0000000000000000;
		limb carry2 = 0x0000000000000000;

		// below is initial product logic
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				limb x1 = a[j] >> 32;
				limb x2 = a[j] & 0x00000000ffffffff;
				limb y1 = b[i] >> 32;
				limb y2 = b[i] & 0x00000000ffffffff;

				limb p1 = y2 * x2;
				limb p2 = y2 * x1;
				limb p3 = y1 * x2;
				limb p4 = y1 * x1;

				limb l1 = p1;
				limb l2 = 0;

				l1 += p2 << 32;
				if (l1 < p2 << 32) l2++;
				l1 += p3 << 32;
				if (l1 < (p3 << 32)) l2++;

				l2 += (p2 >> 32) + (p3 >> 32) + p4;

				limb_products[i][j][0] = l1;
				limb_products[i][j][1] = l2;
			}
		}
		// after the loop, limb_products stores 128bit products of each 64bit limb multiplication without added dangling zeros
		// below is code to convert 4 128bit numbers into 1 512bit number, along with adding necessary dangling zeros for addition later
				/*limb z1 = (y2 * x2) + (y2 * x1) << 32;
				carry1 = (y2 * x1) & 0xffffffff00000000 + (y2 * x2) & 0xffffffff00000000;
				limb z2 = (y1 * x2) + (y1 * x1) << 32;
				carry2 = (y1 * x1) & 0xffffffff00000000 + (y1 * x2) & 0xffffffff00000000;
				z2 = z2 << 32;*/
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				fatty temp = {};
				temp[i + j + 0] = limb_products[i][j][0];
				temp[i + j + 1] = limb_products[i][j][1];
				products[i] = big_add(temp, products[i]); //big add is same as regular add, but works for 512bit numbers

			}
			product = big_add(products[i], product);
		}
		// product has a 512bit product of both 256bit numbers
		return product;
	}

	static inline thiccy mul(const thiccy& a, const thiccy& b) {
		// fatty is 512 bit twice the limbs of thiccy. half thiccy is just 128 bit.
		thiccy result = {};
		fatty product = raw_mul(a, b);
		fatty Psqr = raw_mul(P, P);
		
		// 512 bit product is perfect. now to figure out mod

		return result;
	}
}

namespace private_key{
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
	
}


/// 5 + 9 = 14 = e
/// 0101 | 1001 = 1110 = 14 = e
/// 1000 0101 | 1000 1001
/// 1110
static string create_public_key(string private_key){
	string public_key = "";
	string P = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffc2";
	string k = private_key;

	return public_key;
}



long long modpow(long long a, long long e, long long m) {
	long long res = 1;
	a %= m;
	while (e > 0) {
		if (e & 1) res = (res * a) % m;
		a = (a * a) % m;
		e >>= 1;
	}
	return res;
}

long long moddiv(long long x, long long y, long long z) {
	// z must be prime, y % z != 0
	long long inv = modpow(y, z - 2, z);
	return ((x % z + z) % z * inv) % z;
}

class transaction {
	string sender_public_key;
	string receiver_public_key;
	string signature;
	string tx_hash;
	int value;
	int fee;
};


class block {
	//headers
	vector<transaction> tx;
};

static string get_hash(string input) {
	const char* str = input.c_str();
	char hex[SHA256_HEX_SIZE];
	sha256_hex(str, strlen(str), hex);
	string output(hex);
	return output;
}

int main() {
	//    45 24   504     945   00 = 9 5004
	///   44 21  1056 00 1980 0000
	
	cout << private_key::create_private_key() << endl;

	system("pause > 0");
	return 0;
}