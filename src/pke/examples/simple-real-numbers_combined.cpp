// Derived from simple-real-numbers.cpp - combined timings
#define PROFILE
#include "openfhe.h"
#include "utils/debug.h"
using namespace lbcrypto;

int main() {
    uint32_t multDepth = 22;
    uint32_t scaleModSize = 49;
    uint32_t batchSize = 8;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetSecurityLevel(HEStd_128_classic);
    parameters.SetFirstModSize(50);
    parameters.SetNumLargeDigits(4);
    parameters.SetBatchSize(batchSize);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);

    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);
    cc->EvalRotateKeyGen(keys.secretKey, {1, -2});

    std::vector<double> x1 = {0.25,0.5,0.75,1.0,2.0,3.0,4.0,5.0};
    std::vector<double> x2 = {5.0,4.0,3.0,2.0,1.0,0.75,0.5,0.25};

    uint64_t encode_sum = 0;
    Plaintext p1, p2;
    for (int i = 0; i < 10; ++i) {
        auto s = std::chrono::high_resolution_clock::now();
        p1 = cc->MakeCKKSPackedPlaintext(x1);
        auto e = std::chrono::high_resolution_clock::now();
        encode_sum += std::chrono::duration_cast<std::chrono::microseconds>(e - s).count();

        p2 = cc->MakeCKKSPackedPlaintext(x2);

        s = std::chrono::high_resolution_clock::now();
        Ciphertext<DCRTPoly> c1 = cc->Encrypt(keys.publicKey, p1);
        e = std::chrono::high_resolution_clock::now();
        encode_sum += std::chrono::duration_cast<std::chrono::microseconds>(e - s).count();


    }
    std::cout << "OPENFHE/CKKS/加密 平均: " << encode_sum / 10  << " us" << std::endl;

    // Encrypt to produce ciphertexts
    Ciphertext<DCRTPoly> c1 = cc->Encrypt(keys.publicKey, p1);
    Ciphertext<DCRTPoly> c2 = cc->Encrypt(keys.publicKey, p2);

    // Perform some operations to have ciphertexts to decrypt
    auto cAdd = cc->EvalAdd(c1, c2);
    auto cMul = cc->EvalMult(c1, c2);

    uint64_t dec_sum = 0;
    Plaintext res;
    for (int i = 0; i < 10; ++i) {
        auto d1 = std::chrono::high_resolution_clock::now();
        cc->Decrypt(keys.secretKey, cAdd, &res);
        auto d2 = std::chrono::high_resolution_clock::now();
        dec_sum += std::chrono::duration_cast<std::chrono::microseconds>(d2 - d1).count();
    }
    std::cout << "OPENFHE/CKKS/解密 平均: " << dec_sum / 10 << " us" << std::endl;
    return 0;
}
