// Derived from simple-integers-bgvrns.cpp - add timings
#include "openfhe.h"
using namespace lbcrypto;

int main() {
    CCParams<CryptoContextBGVRNS> parameters;
    ScalingTechnique rescaleTech = FIXEDMANUAL;
    parameters.SetRingDim(32768);
    parameters.SetScalingTechnique(rescaleTech);
    parameters.SetMultiplicativeDepth(14);
    parameters.SetNumLargeDigits(15);
    parameters.SetScalingModSize(55);
    parameters.SetPlaintextModulus(0xC0001);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);

    KeyPair<DCRTPoly> keyPair = cryptoContext->KeyGen();
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);
    cryptoContext->EvalRotateKeyGen(keyPair.secretKey, {1,2,-1,-2});

    size_t vecLen = 32768;
    int64_t modulus = 0xC0001;
    std::vector<int64_t> vectorOfInts1(vecLen), vectorOfInts2(vecLen), vectorOfInts3(vecLen);
    for (size_t i = 0; i < vecLen; ++i) {
        vectorOfInts1[i] = rand() % modulus;
        vectorOfInts2[i] = rand() % modulus;
        vectorOfInts3[i] = rand() % modulus;
    }

    Plaintext p1, p2, p3;
    Ciphertext<DCRTPoly> c1, c2, c3;
    p1 = cryptoContext->MakePackedPlaintext(vectorOfInts1);
    p2 = cryptoContext->MakePackedPlaintext(vectorOfInts2);
    p3 = cryptoContext->MakePackedPlaintext(vectorOfInts3);
    c1 = cryptoContext->Encrypt(keyPair.publicKey, p1);
    c2 = cryptoContext->Encrypt(keyPair.publicKey, p2);
    c3 = cryptoContext->Encrypt(keyPair.publicKey, p3);

    uint64_t add_sum = 0, scalar_add_sum = 0;
    Ciphertext<DCRTPoly> cAdd12, cAddRes, cScalarAdd;
    int64_t scalar = 5;
    Plaintext scalarP = cryptoContext->MakePackedPlaintext(std::vector<int64_t>{scalar});

    for (int i = 0; i < 10; ++i) {
        auto t1 = std::chrono::high_resolution_clock::now();
        cAdd12 = cryptoContext->EvalAdd(c1, c2);
        auto t2 = std::chrono::high_resolution_clock::now();
        add_sum += std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count();

        cAddRes = cryptoContext->EvalAdd(cAdd12, c3);

        t1 = std::chrono::high_resolution_clock::now();
        cScalarAdd = cryptoContext->EvalAdd(c1, scalarP);
        t2 = std::chrono::high_resolution_clock::now();
        scalar_add_sum += std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count();
    }

    std::cout << "OPENFHE/BGV/密文-密文加法 平均: " << add_sum / 10 << " us" << std::endl;
    std::cout << "OPENFHE/BGV/密文-明文加法 平均: " << scalar_add_sum / 10 << " us" << std::endl;
    return 0;
}
