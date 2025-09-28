//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2022, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//
// Author TPOC: contact@openfhe.org
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//==================================================================================

/*
  Simple example for BFVrns (integer arithmetic) - add timings
 */

#include "openfhe.h"

using namespace lbcrypto;

int main() {
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetRingDim(32768);
    parameters.SetMultiplicativeDepth(20);
    parameters.SetKeySwitchTechnique(HYBRID);
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

    Plaintext plaintext1, plaintext2, plaintext3;
    Ciphertext<DCRTPoly> ciphertext1, ciphertext2, ciphertext3;

    // 先编码与加密一次
    plaintext1 = cryptoContext->MakePackedPlaintext(vectorOfInts1);
    plaintext2 = cryptoContext->MakePackedPlaintext(vectorOfInts2);
    plaintext3 = cryptoContext->MakePackedPlaintext(vectorOfInts3);
    ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
    ciphertext2 = cryptoContext->Encrypt(keyPair.publicKey, plaintext2);
    ciphertext3 = cryptoContext->Encrypt(keyPair.publicKey, plaintext3);

    uint64_t add_sum = 0, scalar_add_sum = 0;
    Ciphertext<DCRTPoly> ciphertextAdd12, ciphertextAddResult, ciphertextScalarAdd;
    int64_t scalar = 2;
    Plaintext scalarPlaintext = cryptoContext->MakePackedPlaintext(std::vector<int64_t>{scalar});

    for (int i = 0; i < 10; ++i) {
        auto t1 = std::chrono::high_resolution_clock::now();
        ciphertextAdd12 = cryptoContext->EvalAdd(ciphertext1, ciphertext2);
        auto t2 = std::chrono::high_resolution_clock::now();
        add_sum += std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count();

        ciphertextAddResult = cryptoContext->EvalAdd(ciphertextAdd12, ciphertext3);

        t1 = std::chrono::high_resolution_clock::now();
        ciphertextScalarAdd = cryptoContext->EvalAdd(ciphertext1, scalarPlaintext);
        t2 = std::chrono::high_resolution_clock::now();
        scalar_add_sum += std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count();
    }

    std::cout << "OPENFHE/BFV/密文-密文加法 平均: " << add_sum / 10 << " us" << std::endl;
    std::cout << "OPENFHE/BFV/密文-明文加法 平均: " << scalar_add_sum / 10 << " us" << std::endl;

    return 0;
}
