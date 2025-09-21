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
  Simple examples for CKKS
 */

#define PROFILE

#include "openfhe.h"
#include "utils/debug.h"

using namespace lbcrypto;

int main() {
    // Step 1: Setup CryptoContext

    // A. Specify main parameters
    /* A1) Multiplicative depth:
   * The CKKS scheme we setup here will work for any computation
   * that has a multiplicative depth equal to 'multDepth'.
   * This is the maximum possible depth of a given multiplication,
   * but not the total number of multiplications supported by the
   * scheme.
   *
   * For example, computation f(x, y) = x^2 + x*y + y^2 + x + y has
   * a multiplicative depth of 1, but requires a total of 3 multiplications.
   * On the other hand, computation g(x_i) = x1*x2*x3*x4 can be implemented
   * either as a computation of multiplicative depth 3 as
   * g(x_i) = ((x1*x2)*x3)*x4, or as a computation of multiplicative depth 2
   * as g(x_i) = (x1*x2)*(x3*x4).
   *
   * For performance reasons, it's generally preferable to perform operations
   * in the shorted multiplicative depth possible.
   */
    uint32_t multDepth = 22;

    /* A2) Bit-length of scaling factor.
   * CKKS works for real numbers, but these numbers are encoded as integers.
   * For instance, real number m=0.01 is encoded as m'=round(m*D), where D is
   * a scheme parameter called scaling factor. Suppose D=1000, then m' is 10 (an
   * integer). Say the result of a computation based on m' is 130, then at
   * decryption, the scaling factor is removed so the user is presented with
   * the real number result of 0.13.
   *
   * Parameter 'scaleModSize' determines the bit-length of the scaling
   * factor D, but not the scaling factor itself. The latter is implementation
   * specific, and it may also vary between ciphertexts in certain versions of
   * CKKS (e.g., in FLEXIBLEAUTO).
   *
   * Choosing 'scaleModSize' depends on the desired accuracy of the
   * computation, as well as the remaining parameters like multDepth or security
   * standard. This is because the remaining parameters determine how much noise
   * will be incurred during the computation (remember CKKS is an approximate
   * scheme that incurs small amounts of noise with every operation). The
   * scaling factor should be large enough to both accommodate this noise and
   * support results that match the desired accuracy.
   */
    uint32_t scaleModSize = 49;

    /* A3) Number of plaintext slots used in the ciphertext.
   * CKKS packs multiple plaintext values in each ciphertext.
   * The maximum number of slots depends on a security parameter called ring
   * dimension. In this instance, we don't specify the ring dimension directly,
   * but let the library choose it for us, based on the security level we
   * choose, the multiplicative depth we want to support, and the scaling factor
   * size.
   *
   * Please use method GetRingDimension() to find out the exact ring dimension
   * being used for these parameters. Give ring dimension N, the maximum batch
   * size is N/2, because of the way CKKS works.
   */
    uint32_t batchSize = 8;

    /* A4) Desired security level based on FHE standards.
   * This parameter can take four values. Three of the possible values
   * correspond to 128-bit, 192-bit, and 256-bit security, and the fourth value
   * corresponds to "NotSet", which means that the user is responsible for
   * choosing security parameters. Naturally, "NotSet" should be used only in
   * non-production environments, or by experts who understand the security
   * implications of their choices.
   *
   * If a given security level is selected, the library will consult the current
   * security parameter tables defined by the FHE standards consortium
   * (https://homomorphicencryption.org/introduction/) to automatically
   * select the security parameters. Please see "TABLES of RECOMMENDED
   * PARAMETERS" in  the following reference for more details:
   * http://homomorphicencryption.org/wp-content/uploads/2018/11/HomomorphicEncryptionStandardv1.1.pdf
   */
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);

    parameters.SetScalingModSize(scaleModSize);
    parameters.SetSecurityLevel(HEStd_128_classic);
    parameters.SetFirstModSize(50);
    parameters.SetNumLargeDigits(4);
    parameters.SetBatchSize(batchSize);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    // Enable the features that you wish to use
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);

    // 获取加密参数信息
    const auto cryptoParams  = std::dynamic_pointer_cast<CryptoParametersRNS>(cc->GetCryptoParameters());
    const auto elementParams = cryptoParams->GetElementParams();

    // 打印环维度
    std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension() << std::endl;

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

    std::cout << std::endl;

    // B. Step 2: Key Generation
    /* B1) Generate encryption keys.
   * These are used for encryption/decryption, as well as in generating
   * different kinds of keys.
   */
    auto keys = cc->KeyGen();

    /* B2) Generate the digit size
   * In CKKS, whenever someone multiplies two ciphertexts encrypted with key s,
   * we get a result with some components that are valid under key s, and
   * with an additional component that's valid under key s^2.
   *
   * In most cases, we want to perform relinearization of the multiplicaiton
   * result, i.e., we want to transform the s^2 component of the ciphertext so
   * it becomes valid under original key s. To do so, we need to create what we
   * call a relinearization key with the following line.
   */
    cc->EvalMultKeyGen(keys.secretKey);

    /* B3) Generate the rotation keys
   * CKKS supports rotating the contents of a packed ciphertext, but to do so,
   * we need to create what we call a rotation key. This is done with the
   * following call, which takes as input a vector with indices that correspond
   * to the rotation offset we want to support. Negative indices correspond to
   * right shift and positive to left shift. Look at the output of this demo for
   * an illustration of this.
   *
   * Keep in mind that rotations work over the batch size or entire ring dimension (if the batch size is not specified).
   * This means that, if ring dimension is 8 and batch
   * size is not specified, then an input (1,2,3,4,0,0,0,0) rotated by 2 will become
   * (3,4,0,0,0,0,1,2) and not (3,4,1,2,0,0,0,0).
   * If ring dimension is 8 and batch
   * size is set to 4, then the rotation of (1,2,3,4) by 2 will become (3,4,1,2).
   * Also, as someone can observe
   * in the output of this demo, since CKKS is approximate, zeros are not exact
   * - they're just very small numbers.
   */
    cc->EvalRotateKeyGen(keys.secretKey, {1, -2});

    // Step 3: Encoding and encryption of inputs

    // Inputs
    std::vector<double> x1 = {0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0};
    std::vector<double> x2 = {5.0, 4.0, 3.0, 2.0, 1.0, 0.75, 0.5, 0.25};

    // 编码计时（微秒级）
    auto encode_start = std::chrono::high_resolution_clock::now();
    Plaintext ptxt1   = cc->MakeCKKSPackedPlaintext(x1);
    auto encode_end   = std::chrono::high_resolution_clock::now();
    auto encode_us    = std::chrono::duration_cast<std::chrono::microseconds>(encode_end - encode_start).count();
    std::cout << "编码 x1 (Encode): " << encode_us << " us" << std::endl;

    encode_start    = std::chrono::high_resolution_clock::now();
    Plaintext ptxt2 = cc->MakeCKKSPackedPlaintext(x2);
    encode_end      = std::chrono::high_resolution_clock::now();
    encode_us       = std::chrono::duration_cast<std::chrono::microseconds>(encode_end - encode_start).count();
    std::cout << "编码 x2 (Encode): " << encode_us << " us" << std::endl;

    std::cout << "Input x1: " << ptxt1 << std::endl;
    std::cout << "Input x2: " << ptxt2 << std::endl;

    // 加密操作计时（微秒级）
    std::cout << "\n======= 加解密操作时间 =======" << std::endl;
    auto op_start = std::chrono::high_resolution_clock::now();
    auto c1       = cc->Encrypt(keys.publicKey, ptxt1);
    auto op_end   = std::chrono::high_resolution_clock::now();
    auto op_us    = std::chrono::duration_cast<std::chrono::microseconds>(op_end - op_start).count();
    std::cout << "加密 x1 (Encrypt): " << op_us << " us" << std::endl;

    op_start = std::chrono::high_resolution_clock::now();
    auto c2  = cc->Encrypt(keys.publicKey, ptxt2);
    op_end   = std::chrono::high_resolution_clock::now();
    op_us    = std::chrono::duration_cast<std::chrono::microseconds>(op_end - op_start).count();
    std::cout << "加密 x2 (Encrypt): " << op_us << " us" << std::endl;

    // Step 4: Evaluation
    std::cout << "\n======= 操作执行时间 =======" << std::endl;

    // 同态加法 (Homomorphic addition)
    op_start  = std::chrono::high_resolution_clock::now();
    auto cAdd = cc->EvalAdd(c1, c2);
    op_end    = std::chrono::high_resolution_clock::now();
    op_us     = std::chrono::duration_cast<std::chrono::microseconds>(op_end - op_start).count();
    std::cout << "同态加法 (EvalAdd): " << op_us << " us" << std::endl;

    // 同态减法 (Homomorphic subtraction)
    op_start  = std::chrono::high_resolution_clock::now();
    auto cSub = cc->EvalSub(c1, c2);
    op_end    = std::chrono::high_resolution_clock::now();
    op_us     = std::chrono::duration_cast<std::chrono::microseconds>(op_end - op_start).count();
    std::cout << "同态减法 (EvalSub): " << op_us << " us" << std::endl;

    // 常量加法 (Constant addition)
    op_start       = std::chrono::high_resolution_clock::now();
    auto cAddConst = cc->EvalAdd(c1, 2.5);
    op_end         = std::chrono::high_resolution_clock::now();
    op_us          = std::chrono::duration_cast<std::chrono::microseconds>(op_end - op_start).count();
    std::cout << "常量加法 (EvalAdd scalar): " << op_us << " us" << std::endl;

    // 同态乘法标量 (Homomorphic scalar multiplication)
    op_start     = std::chrono::high_resolution_clock::now();
    auto cScalar = cc->EvalMult(c1, 4.0);
    op_end       = std::chrono::high_resolution_clock::now();
    op_us        = std::chrono::duration_cast<std::chrono::microseconds>(op_end - op_start).count();
    std::cout << "标量乘法 (EvalMult scalar): " << op_us << " us" << std::endl;

    // 同态乘法 (Homomorphic multiplication)
    op_start  = std::chrono::high_resolution_clock::now();
    auto cMul = cc->EvalMult(c1, c2);
    op_end    = std::chrono::high_resolution_clock::now();
    op_us     = std::chrono::duration_cast<std::chrono::microseconds>(op_end - op_start).count();
    std::cout << "同态乘法 (EvalMult): " << op_us << " us" << std::endl;

    // 同态旋转 (Homomorphic rotations)
    op_start   = std::chrono::high_resolution_clock::now();
    auto cRot1 = cc->EvalRotate(c1, 1);
    op_end     = std::chrono::high_resolution_clock::now();
    op_us      = std::chrono::duration_cast<std::chrono::microseconds>(op_end - op_start).count();
    std::cout << "同态旋转 +1 (EvalRotate): " << op_us << " us" << std::endl;

    op_start   = std::chrono::high_resolution_clock::now();
    auto cRot2 = cc->EvalRotate(c1, -2);
    op_end     = std::chrono::high_resolution_clock::now();
    op_us      = std::chrono::duration_cast<std::chrono::microseconds>(op_end - op_start).count();
    std::cout << "同态旋转 -2 (EvalRotate): " << op_us << " us" << std::endl;

    // Step 5: Decryption and output
    Plaintext result;
    std::cout.precision(8);

    std::cout << std::endl << "Results of homomorphic computations: " << std::endl;

    // 解码计时（微秒级）
    auto decode_start = std::chrono::high_resolution_clock::now();
    cc->Decrypt(keys.secretKey, c1, &result);
    auto decode_end = std::chrono::high_resolution_clock::now();
    auto decode_us  = std::chrono::duration_cast<std::chrono::microseconds>(decode_end - decode_start).count();
    std::cout << "解密 x1 (Decrypt): " << decode_us << " us" << std::endl;
    result->SetLength(batchSize);
    std::cout << "x1 = " << result;
    std::cout << "Estimated precision in bits: " << result->GetLogPrecision() << std::endl;

    decode_start = std::chrono::high_resolution_clock::now();
    cc->Decrypt(keys.secretKey, cAdd, &result);
    decode_end = std::chrono::high_resolution_clock::now();
    decode_us  = std::chrono::duration_cast<std::chrono::microseconds>(decode_end - decode_start).count();
    result->SetLength(batchSize);
    std::cout << "x1 + x2 = " << result;
    std::cout << "解密 x1+x2 (Decrypt): " << decode_us << " us" << std::endl;
    std::cout << "Estimated precision in bits: " << result->GetLogPrecision() << std::endl;

    decode_start = std::chrono::high_resolution_clock::now();
    cc->Decrypt(keys.secretKey, cSub, &result);
    decode_end = std::chrono::high_resolution_clock::now();
    decode_us  = std::chrono::duration_cast<std::chrono::microseconds>(decode_end - decode_start).count();
    result->SetLength(batchSize);
    std::cout << "x1 - x2 = " << result << std::endl;
    std::cout << "解密 x1-x2 (Decrypt): " << decode_us << " us" << std::endl;

    decode_start = std::chrono::high_resolution_clock::now();
    cc->Decrypt(keys.secretKey, cAddConst, &result);
    decode_end = std::chrono::high_resolution_clock::now();
    decode_us  = std::chrono::duration_cast<std::chrono::microseconds>(decode_end - decode_start).count();
    result->SetLength(batchSize);
    std::cout << "x1 + 2.5 = " << result << std::endl;
    std::cout << "解密 x1+2.5 (Decrypt): " << decode_us << " us" << std::endl;

    decode_start = std::chrono::high_resolution_clock::now();
    cc->Decrypt(keys.secretKey, cScalar, &result);
    decode_end = std::chrono::high_resolution_clock::now();
    decode_us  = std::chrono::duration_cast<std::chrono::microseconds>(decode_end - decode_start).count();
    result->SetLength(batchSize);
    std::cout << "4 * x1 = " << result << std::endl;
    std::cout << "解密 4*x1 (Decrypt): " << decode_us << " us" << std::endl;

    decode_start = std::chrono::high_resolution_clock::now();
    cc->Decrypt(keys.secretKey, cMul, &result);
    decode_end = std::chrono::high_resolution_clock::now();
    decode_us  = std::chrono::duration_cast<std::chrono::microseconds>(decode_end - decode_start).count();
    result->SetLength(batchSize);
    std::cout << "x1 * x2 = " << result << std::endl;
    std::cout << "解密 x1*x2 (Decrypt): " << decode_us << " us" << std::endl;

    decode_start = std::chrono::high_resolution_clock::now();
    cc->Decrypt(keys.secretKey, cRot1, &result);
    decode_end = std::chrono::high_resolution_clock::now();
    decode_us  = std::chrono::duration_cast<std::chrono::microseconds>(decode_end - decode_start).count();
    result->SetLength(batchSize);
    std::cout << std::endl << "In rotations, very small outputs (~10^-10 here) correspond to 0's:" << std::endl;
    std::cout << "x1 rotate by 1 = " << result << std::endl;
    std::cout << "解密 x1旋转+1 (Decrypt): " << decode_us << " us" << std::endl;

    decode_start = std::chrono::high_resolution_clock::now();
    cc->Decrypt(keys.secretKey, cRot2, &result);
    decode_end = std::chrono::high_resolution_clock::now();
    decode_us  = std::chrono::duration_cast<std::chrono::microseconds>(decode_end - decode_start).count();
    result->SetLength(batchSize);
    std::cout << "x1 rotate by -2 = " << result << std::endl;
    std::cout << "解密 x1旋转-2 (Decrypt): " << decode_us << " us" << std::endl;

    return 0;
}
