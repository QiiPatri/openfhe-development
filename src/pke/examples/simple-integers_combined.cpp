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
  Simple example for BFVrns (integer arithmetic) - combined timings
 */

#include "openfhe.h"

using namespace lbcrypto;

int main() {
    // Sample Program: Step 1: Set CryptoContext
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

    // 参数信息（略）
    const auto cryptoParams  = std::dynamic_pointer_cast<CryptoParametersRNS>(cryptoContext->GetCryptoParameters());
    const auto elementParams = cryptoParams->GetElementParams();

    std::cout << "BFV scheme is using ring dimension " << cryptoContext->GetRingDimension() << std::endl;

    // KeyGen
    KeyPair<DCRTPoly> keyPair = cryptoContext->KeyGen();
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);
    cryptoContext->EvalRotateKeyGen(keyPair.secretKey, {1,2,-1,-2});

    // Prepare data
    size_t vecLen = 32768;
    int64_t modulus = 0xC0001;
    std::vector<int64_t> vectorOfInts1(vecLen), vectorOfInts2(vecLen), vectorOfInts3(vecLen);
    for (size_t i = 0; i < vecLen; ++i) {
        vectorOfInts1[i] = rand() % modulus;
        vectorOfInts2[i] = rand() % modulus;
        vectorOfInts3[i] = rand() % modulus;
    }

    // 编码 + 加密 计时（合并）
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

    std::cout << "OPENFHE/BFV/加密 平均: " << encode_sum / 30 << " us" << std::endl;

    // 执行若干操作以得到待解密的 ciphertexts
    auto ciphertextAdd12 = cryptoContext->EvalAdd(ciphertext1, ciphertext2);
    auto ciphertextAddResult = cryptoContext->EvalAdd(ciphertextAdd12, ciphertext3);
    auto ciphertextMul12 = cryptoContext->EvalMult(ciphertext1, ciphertext2);
    auto ciphertextMultResult = cryptoContext->EvalMult(ciphertextMul12, ciphertext3);

    auto ciphertextRot1 = cryptoContext->EvalRotate(ciphertext1, 1);
    auto ciphertextRot2 = cryptoContext->EvalRotate(ciphertext1, 2);
    auto ciphertextRot3 = cryptoContext->EvalRotate(ciphertext1, -1);
    auto ciphertextRot4 = cryptoContext->EvalRotate(ciphertext1, -2);

    // 解密 + 解码 计时（合并）：对上面 6 个结果做 10 次解密计时
    uint64_t dec_sum = 0;
    Plaintext ptAddResult, ptMultResult, ptRot1, ptRot2, ptRot3, ptRot4;
    for (int i = 0; i < 10; ++i) {
        auto d1 = std::chrono::high_resolution_clock::now();
        cryptoContext->Decrypt(keyPair.secretKey, ciphertextAddResult, &ptAddResult);
        auto d2 = std::chrono::high_resolution_clock::now();
        dec_sum += std::chrono::duration_cast<std::chrono::microseconds>(d2 - d1).count();
        cryptoContext->Decrypt(keyPair.secretKey, ciphertextMultResult, &ptMultResult);
        cryptoContext->Decrypt(keyPair.secretKey, ciphertextRot1, &ptRot1);
        cryptoContext->Decrypt(keyPair.secretKey, ciphertextRot2, &ptRot2);
        cryptoContext->Decrypt(keyPair.secretKey, ciphertextRot3, &ptRot3);
        cryptoContext->Decrypt(keyPair.secretKey, ciphertextRot4, &ptRot4);

    }

    std::cout << "OPENFHE/BFV/解密 平均: " << dec_sum / 10 << " us" << std::endl;

    return 0;
}
