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
  Simple example for BGVrns (integer arithmetic)
 */

#include "openfhe.h"

using namespace lbcrypto;

int main() {
    // Sample Program: Step 1 - Set CryptoContext
    CCParams<CryptoContextBGVRNS> parameters;
    ScalingTechnique rescaleTech = FIXEDMANUAL;
    parameters.SetRingDim(32768);
    parameters.SetScalingTechnique(rescaleTech);
    // parameters.SetSecurityLevel(HEStd_128_classic);
    parameters.SetMultiplicativeDepth(14);
    parameters.SetNumLargeDigits(15);
    parameters.SetScalingModSize(55);
    parameters.SetPlaintextModulus(0xC0001);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    // Enable features that you wish to use
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);

    // 获取加密参数信息
    const auto cryptoParams  = std::dynamic_pointer_cast<CryptoParametersRNS>(cryptoContext->GetCryptoParameters());
    const auto elementParams = cryptoParams->GetElementParams();

    // 打印环维度
    std::cout << "BGV scheme is using ring dimension " << cryptoContext->GetRingDimension() << std::endl;

    // 打印模数链长度（q的个数）
    size_t numQ = elementParams->GetParams().size();
    std::cout << "Number of moduli in ciphertext modulus chain (q): " << numQ << std::endl;

    // 打印所有q值
    std::cout << "Moduli q values: " << std::endl;
    for (size_t i = 0; i < numQ; i++) {
        auto params = elementParams->GetParams();
        std::cout << "q[" << i << "]: " << params[i]->GetModulus() << std::endl;
    }

    // 尝试获取和打印所有p值
    try {
        // 获取特殊素数信息
        const auto paramsP = cryptoParams->GetParamsP();
        if (paramsP != nullptr) {
            size_t numP = paramsP->GetParams().size();
            std::cout << "\nNumber of special primes (p): " << numP << std::endl;

            // 打印所有p值
            std::cout << "Special primes p values: " << std::endl;
            for (size_t i = 0; i < numP; i++) {
                auto paramP = paramsP->GetParams();
                std::cout << "p[" << i << "]: " << paramP[i]->GetModulus() << std::endl;
            }
        }
        else {
            std::cout << "\nNo special primes (p) are used in current configuration." << std::endl;
        }

        // 打印辅助信息
        std::cout << "\nKey switching technique: ";
        switch (cryptoParams->GetKeySwitchTechnique()) {
            case BV:
                std::cout << "BV (no special primes)" << std::endl;
                break;
            case HYBRID:
                std::cout << "HYBRID with " << cryptoParams->GetNumberOfQPartitions() << " partitions" << std::endl;
                std::cout << "Alpha (towers per digit): " << cryptoParams->GetNumPerPartQ() << std::endl;
                break;
            default:
                std::cout << "Unknown" << std::endl;
        }
    }
    catch (const std::exception& e) {
        std::cout << "\nCould not determine special primes: " << e.what() << std::endl;
    }

    // Sample Program: Step 2 - Key Generation

    // Initialize Public Key Containers
    KeyPair<DCRTPoly> keyPair;

    // Generate a public/private key pair
    keyPair = cryptoContext->KeyGen();

    // Generate the relinearization key
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);

    // Generate the rotation evaluation keys
    cryptoContext->EvalRotateKeyGen(keyPair.secretKey, {1, 2, -1, -2});

    // Sample Program: Step 3 - Encryption

    // 编码计时（微秒级，循环10次取平均）
    size_t vecLen = 32768;
    int64_t modulus = 0xC0001;
    std::vector<int64_t> vectorOfInts1(vecLen), vectorOfInts2(vecLen), vectorOfInts3(vecLen);
    for (size_t i = 0; i < vecLen; ++i) {
        vectorOfInts1[i] = rand() % modulus;
        vectorOfInts2[i] = rand() % modulus;
        vectorOfInts3[i] = rand() % modulus;
    }
    uint64_t encode_sum1 = 0, encode_sum2 = 0, encode_sum3 = 0;
    Plaintext plaintext1, plaintext2, plaintext3;
    for (int i = 0; i < 10; ++i) {
        auto encode_start = std::chrono::high_resolution_clock::now();
        plaintext1        = cryptoContext->MakePackedPlaintext(vectorOfInts1);
        auto encode_end   = std::chrono::high_resolution_clock::now();
        encode_sum1 += std::chrono::duration_cast<std::chrono::microseconds>(encode_end - encode_start).count();

        encode_start = std::chrono::high_resolution_clock::now();
        plaintext2   = cryptoContext->MakePackedPlaintext(vectorOfInts2);
        encode_end   = std::chrono::high_resolution_clock::now();
        encode_sum2 += std::chrono::duration_cast<std::chrono::microseconds>(encode_end - encode_start).count();

        encode_start = std::chrono::high_resolution_clock::now();
        plaintext3   = cryptoContext->MakePackedPlaintext(vectorOfInts3);
        encode_end   = std::chrono::high_resolution_clock::now();
        encode_sum3 += std::chrono::duration_cast<std::chrono::microseconds>(encode_end - encode_start).count();
    }
    std::cout << "编码 #1 平均: " << encode_sum1 / 10 << " us" << std::endl;
    std::cout << "编码 #2 平均: " << encode_sum2 / 10 << " us" << std::endl;
    std::cout << "编码 #3 平均: " << encode_sum3 / 10 << " us" << std::endl;

    // 加密计时（微秒级，循环10次取平均）
    uint64_t enc_sum1 = 0, enc_sum2 = 0, enc_sum3 = 0;
    Ciphertext<DCRTPoly> ciphertext1, ciphertext2, ciphertext3;
    for (int i = 0; i < 10; ++i) {
        auto op_start = std::chrono::high_resolution_clock::now();
        ciphertext1   = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
        auto op_end   = std::chrono::high_resolution_clock::now();
        enc_sum1 += std::chrono::duration_cast<std::chrono::microseconds>(op_end - op_start).count();

        op_start    = std::chrono::high_resolution_clock::now();
        ciphertext2 = cryptoContext->Encrypt(keyPair.publicKey, plaintext2);
        op_end      = std::chrono::high_resolution_clock::now();
        enc_sum2 += std::chrono::duration_cast<std::chrono::microseconds>(op_end - op_start).count();

        op_start    = std::chrono::high_resolution_clock::now();
        ciphertext3 = cryptoContext->Encrypt(keyPair.publicKey, plaintext3);
        op_end      = std::chrono::high_resolution_clock::now();
        enc_sum3 += std::chrono::duration_cast<std::chrono::microseconds>(op_end - op_start).count();
    }
    std::cout << "加密 #1 平均: " << enc_sum1 / 10 << " us" << std::endl;
    std::cout << "加密 #2 平均: " << enc_sum2 / 10 << " us" << std::endl;
    std::cout << "加密 #3 平均: " << enc_sum3 / 10 << " us" << std::endl;

    // Sample Program: Step 4 - Evaluation

    // 同态运算计时（微秒级，循环10次取平均）
    uint64_t add_sum = 0, mult_sum = 0, scalar_add_sum = 0, scalar_mult_sum = 0, rot1_sum = 0, rot2_sum = 0,
             rot3_sum = 0, rot4_sum = 0;
    Ciphertext<DCRTPoly> ciphertextAdd12, ciphertextAddResult;
    Ciphertext<DCRTPoly> ciphertextMul12, ciphertextMultResult;
    Ciphertext<DCRTPoly> ciphertextScalarAdd, ciphertextScalarMult;
    Ciphertext<DCRTPoly> ciphertextRot1, ciphertextRot2, ciphertextRot3, ciphertextRot4;
    int64_t scalar            = 5;  // 可自定义标量值
    Plaintext scalarPlaintext = cryptoContext->MakePackedPlaintext(std::vector<int64_t>{scalar});

    for (int i = 0; i < 10; ++i) {
        // 同态加法
        auto op_start   = std::chrono::high_resolution_clock::now();
        ciphertextAdd12 = cryptoContext->EvalAdd(ciphertext1, ciphertext2);

        auto op_end = std::chrono::high_resolution_clock::now();
        add_sum += std::chrono::duration_cast<std::chrono::microseconds>(op_end - op_start).count();

        ciphertextAddResult = cryptoContext->EvalAdd(ciphertextAdd12, ciphertext3);
        // 标量加法
        op_start            = std::chrono::high_resolution_clock::now();
        ciphertextScalarAdd = cryptoContext->EvalAdd(ciphertext1, scalarPlaintext);

        op_end = std::chrono::high_resolution_clock::now();
        scalar_add_sum += std::chrono::duration_cast<std::chrono::microseconds>(op_end - op_start).count();

        // 同态乘法
        op_start        = std::chrono::high_resolution_clock::now();
        ciphertextMul12 = cryptoContext->EvalMult(ciphertext1, ciphertext2);

        op_end = std::chrono::high_resolution_clock::now();
        mult_sum += std::chrono::duration_cast<std::chrono::microseconds>(op_end - op_start).count();

        ciphertextMultResult = cryptoContext->EvalMult(ciphertextMul12, ciphertext3);
        // 标量乘法
        op_start             = std::chrono::high_resolution_clock::now();
        ciphertextScalarMult = cryptoContext->EvalMult(ciphertext1, scalarPlaintext);
        op_end               = std::chrono::high_resolution_clock::now();
        scalar_mult_sum += std::chrono::duration_cast<std::chrono::microseconds>(op_end - op_start).count();

        // 旋转
        op_start       = std::chrono::high_resolution_clock::now();
        ciphertextRot1 = cryptoContext->EvalRotate(ciphertext1, 1);
        op_end         = std::chrono::high_resolution_clock::now();
        rot1_sum += std::chrono::duration_cast<std::chrono::microseconds>(op_end - op_start).count();

        op_start       = std::chrono::high_resolution_clock::now();
        ciphertextRot2 = cryptoContext->EvalRotate(ciphertext1, 2);
        op_end         = std::chrono::high_resolution_clock::now();
        rot2_sum += std::chrono::duration_cast<std::chrono::microseconds>(op_end - op_start).count();

        op_start       = std::chrono::high_resolution_clock::now();
        ciphertextRot3 = cryptoContext->EvalRotate(ciphertext1, -1);
        op_end         = std::chrono::high_resolution_clock::now();
        rot3_sum += std::chrono::duration_cast<std::chrono::microseconds>(op_end - op_start).count();

        op_start       = std::chrono::high_resolution_clock::now();
        ciphertextRot4 = cryptoContext->EvalRotate(ciphertext1, -2);
        op_end         = std::chrono::high_resolution_clock::now();
        rot4_sum += std::chrono::duration_cast<std::chrono::microseconds>(op_end - op_start).count();
    }
    std::cout << "同态加法 (EvalAdd) 平均: " << add_sum / 10 << " us" << std::endl;
    std::cout << "标量加法 (EvalAdd scalar) 平均: " << scalar_add_sum / 10 << " us" << std::endl;
    std::cout << "同态乘法 (EvalMult) 平均: " << mult_sum / 10 << " us" << std::endl;
    std::cout << "标量乘法 (EvalMult scalar) 平均: " << scalar_mult_sum / 10 << " us" << std::endl;
    std::cout << "左旋1 (EvalRotate) 平均: " << rot1_sum / 10 << " us" << std::endl;
    std::cout << "左旋2 (EvalRotate) 平均: " << rot2_sum / 10 << " us" << std::endl;
    std::cout << "右旋1 (EvalRotate) 平均: " << rot3_sum / 10 << " us" << std::endl;
    std::cout << "右旋2 (EvalRotate) 平均: " << rot4_sum / 10 << " us" << std::endl;

    // Sample Program: Step 5 - Decryption

    // 解密计时（微秒级，循环10次取平均）
    uint64_t dec_sumAdd = 0, dec_sumMult = 0, dec_sumRot1 = 0, dec_sumRot2 = 0, dec_sumRot3 = 0, dec_sumRot4 = 0;
    Plaintext plaintextAddResult, plaintextMultResult, plaintextRot1, plaintextRot2, plaintextRot3, plaintextRot4;
    for (int i = 0; i < 10; ++i) {
        auto decode_start = std::chrono::high_resolution_clock::now();
        cryptoContext->Decrypt(keyPair.secretKey, ciphertextAddResult, &plaintextAddResult);
        auto decode_end = std::chrono::high_resolution_clock::now();
        dec_sumAdd += std::chrono::duration_cast<std::chrono::microseconds>(decode_end - decode_start).count();

        decode_start = std::chrono::high_resolution_clock::now();
        cryptoContext->Decrypt(keyPair.secretKey, ciphertextMultResult, &plaintextMultResult);
        decode_end = std::chrono::high_resolution_clock::now();
        dec_sumMult += std::chrono::duration_cast<std::chrono::microseconds>(decode_end - decode_start).count();

        decode_start = std::chrono::high_resolution_clock::now();
        cryptoContext->Decrypt(keyPair.secretKey, ciphertextRot1, &plaintextRot1);
        decode_end = std::chrono::high_resolution_clock::now();
        dec_sumRot1 += std::chrono::duration_cast<std::chrono::microseconds>(decode_end - decode_start).count();

        decode_start = std::chrono::high_resolution_clock::now();
        cryptoContext->Decrypt(keyPair.secretKey, ciphertextRot2, &plaintextRot2);
        decode_end = std::chrono::high_resolution_clock::now();
        dec_sumRot2 += std::chrono::duration_cast<std::chrono::microseconds>(decode_end - decode_start).count();

        decode_start = std::chrono::high_resolution_clock::now();
        cryptoContext->Decrypt(keyPair.secretKey, ciphertextRot3, &plaintextRot3);
        decode_end = std::chrono::high_resolution_clock::now();
        dec_sumRot3 += std::chrono::duration_cast<std::chrono::microseconds>(decode_end - decode_start).count();

        decode_start = std::chrono::high_resolution_clock::now();
        cryptoContext->Decrypt(keyPair.secretKey, ciphertextRot4, &plaintextRot4);
        decode_end = std::chrono::high_resolution_clock::now();
        dec_sumRot4 += std::chrono::duration_cast<std::chrono::microseconds>(decode_end - decode_start).count();
    }
    plaintextRot1->SetLength(vectorOfInts1.size());
    plaintextRot2->SetLength(vectorOfInts1.size());
    plaintextRot3->SetLength(vectorOfInts1.size());
    plaintextRot4->SetLength(vectorOfInts1.size());
    std::cout << "解密加法 (Decrypt) 平均: " << dec_sumAdd / 10 << " us" << std::endl;
    std::cout << "解密乘法 (Decrypt) 平均: " << dec_sumMult / 10 << " us" << std::endl;
    std::cout << "解密左旋1 (Decrypt) 平均: " << dec_sumRot1 / 10 << " us" << std::endl;
    std::cout << "解密左旋2 (Decrypt) 平均: " << dec_sumRot2 / 10 << " us" << std::endl;
    std::cout << "解密右旋1 (Decrypt) 平均: " << dec_sumRot3 / 10 << " us" << std::endl;
    std::cout << "解密右旋2 (Decrypt) 平均: " << dec_sumRot4 / 10 << " us" << std::endl;

    // std::cout << "Plaintext #1: " << plaintext1 << std::endl;
    // std::cout << "Plaintext #2: " << plaintext2 << std::endl;
    // std::cout << "Plaintext #3: " << plaintext3 << std::endl;

    // // Output results
    // std::cout << "\nResults of homomorphic computations" << std::endl;
    // std::cout << "#1 + #2 + #3: " << plaintextAddResult << std::endl;
    // std::cout << "#1 * #2 * #3: " << plaintextMultResult << std::endl;
    // std::cout << "Left rotation of #1 by 1: " << plaintextRot1 << std::endl;
    // std::cout << "Left rotation of #1 by 2: " << plaintextRot2 << std::endl;
    // std::cout << "Right rotation of #1 by 1: " << plaintextRot3 << std::endl;
    // std::cout << "Right rotation of #1 by 2: " << plaintextRot4 << std::endl;

    return 0;
}
