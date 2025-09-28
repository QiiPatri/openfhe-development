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

    Plaintext p1 = cc->MakeCKKSPackedPlaintext(x1);
    Plaintext p2 = cc->MakeCKKSPackedPlaintext(x2);
    Ciphertext<DCRTPoly> c1 = cc->Encrypt(keys.publicKey, p1);
    Ciphertext<DCRTPoly> c2 = cc->Encrypt(keys.publicKey, p2);

    uint64_t mult_sum = 0, scalar_mult_sum = 0;
    Ciphertext<DCRTPoly> cMul, cScalar;

    for (int i = 0; i < 10; ++i) {
        auto s = std::chrono::high_resolution_clock::now();
        cMul = cc->EvalMult(c1, c2);
        auto e = std::chrono::high_resolution_clock::now();
        mult_sum += std::chrono::duration_cast<std::chrono::microseconds>(e - s).count();

        s = std::chrono::high_resolution_clock::now();
        cScalar = cc->EvalMult(c1, p1);
        e = std::chrono::high_resolution_clock::now();
        scalar_mult_sum += std::chrono::duration_cast<std::chrono::microseconds>(e - s).count();
    }

    std::cout << "OPENFHE/CKKS/同态乘法 平均: " << mult_sum / 10 << " us" << std::endl;
    std::cout << "OPENFHE/CKKS/标量乘法 平均: " << scalar_mult_sum / 10 << " us" << std::endl;
    return 0;
}
