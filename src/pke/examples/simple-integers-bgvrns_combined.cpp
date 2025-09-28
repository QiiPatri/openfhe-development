// Derived from simple-integers-bgvrns.cpp - combined timings
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

    uint64_t encode_sum = 0;
    Plaintext plaintext1, plaintext2, plaintext3;
    Ciphertext<DCRTPoly> ciphertext1, ciphertext2, ciphertext3;
    for (int i = 0; i < 10; ++i) {
        auto t1 = std::chrono::high_resolution_clock::now();
        plaintext1 = cryptoContext->MakePackedPlaintext(vectorOfInts1);
        ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
        auto t2 = std::chrono::high_resolution_clock::now();
        encode_sum += std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count();

        t1 = std::chrono::high_resolution_clock::now();
        plaintext2 = cryptoContext->MakePackedPlaintext(vectorOfInts2);
        ciphertext2 = cryptoContext->Encrypt(keyPair.publicKey, plaintext2);
        t2 = std::chrono::high_resolution_clock::now();
        encode_sum += std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count();

        t1 = std::chrono::high_resolution_clock::now();
        plaintext3 = cryptoContext->MakePackedPlaintext(vectorOfInts3);
        ciphertext3 = cryptoContext->Encrypt(keyPair.publicKey, plaintext3);
        t2 = std::chrono::high_resolution_clock::now();
        encode_sum += std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count();
    }

    std::cout << "OPENFHE/BGV/加密 平均: " << encode_sum / 30 << " us" << std::endl;

    auto cAdd12 = cryptoContext->EvalAdd(ciphertext1, ciphertext2);
    auto cAddRes = cryptoContext->EvalAdd(cAdd12, ciphertext3);
    auto cMul12 = cryptoContext->EvalMult(ciphertext1, ciphertext2);
    auto cMulRes = cryptoContext->EvalMult(cMul12, ciphertext3);

    auto cRot1 = cryptoContext->EvalRotate(ciphertext1, 1);
    auto cRot2 = cryptoContext->EvalRotate(ciphertext1, 2);
    auto cRot3 = cryptoContext->EvalRotate(ciphertext1, -1);
    auto cRot4 = cryptoContext->EvalRotate(ciphertext1, -2);

    uint64_t dec_sum = 0;
    Plaintext pt;
    for (int i = 0; i < 10; ++i) {
        auto d1 = std::chrono::high_resolution_clock::now();
        cryptoContext->Decrypt(keyPair.secretKey, cAddRes, &pt);
        auto d2 = std::chrono::high_resolution_clock::now();
        dec_sum += std::chrono::duration_cast<std::chrono::microseconds>(d2 - d1).count();
        cryptoContext->Decrypt(keyPair.secretKey, cMulRes, &pt);
        cryptoContext->Decrypt(keyPair.secretKey, cRot1, &pt);
        cryptoContext->Decrypt(keyPair.secretKey, cRot2, &pt);
        cryptoContext->Decrypt(keyPair.secretKey, cRot3, &pt);
        cryptoContext->Decrypt(keyPair.secretKey, cRot4, &pt);
    }

    std::cout << "OPENFHE/BGV/解密 平均: " << dec_sum / 10 << " us" << std::endl;
    return 0;
}
