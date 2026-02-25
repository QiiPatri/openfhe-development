#include "openfhe.h"

#include <algorithm>
#include <chrono>
#include <complex>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace lbcrypto;

namespace {

constexpr std::size_t kFeatureDim = 196;                  // pixels per MNIST row in the data file
constexpr std::size_t kVectorDim = kFeatureDim + 1;        // bias slot + pixels
constexpr std::size_t kBatchSize = 256;                    // CKKS packing slots we plan to use
const std::string kDefaultMnistPath = "../../../../src/pke/examples/data/MNIST_test.txt";
const std::string kDefaultOmegaPath = "../../../../src/pke/examples/data/omega.txt";

struct SampleRow {
    int label = 0;
    std::vector<double> slots; // already padded to kBatchSize
};

std::vector<int32_t> BuildRotationKeySteps(std::size_t usedSlots) {
    std::vector<int32_t> steps;
    for (std::size_t step = 1; step < usedSlots; step <<= 1) {
        steps.push_back(static_cast<int32_t>(step));
    }
    return steps;
}

std::vector<double> LoadOmegaSlots(const std::string& path) {
    std::ifstream input(path);
    if (!input.is_open()) {
        throw std::runtime_error("Unable to open omega file: " + path);
    }

    std::vector<double> raw;
    double value = 0.0;
    while (input >> value) {
        raw.push_back(value);
    }

    if (raw.size() != kVectorDim) {
        throw std::runtime_error("omega length mismatch: expected " + std::to_string(kVectorDim) +
                                 ", got " + std::to_string(raw.size()));
    }

    std::vector<double> slots(kBatchSize, 0.0);
    std::copy(raw.begin(), raw.end(), slots.begin());
    return slots;
}

SampleRow ParseMnistLine(const std::string& line) {
    SampleRow row;
    row.slots.assign(kBatchSize, 0.0);

    std::stringstream ss(line);
    std::string cell;

    if (!std::getline(ss, cell, ',')) {
        throw std::runtime_error("Malformed MNIST row: missing label");
    }

    row.label = std::stoi(cell);
    row.slots[0] = 1.0; // homomorphic bias slot

    std::size_t featureIdx = 1;
    while (featureIdx < kVectorDim && std::getline(ss, cell, ',')) {
        row.slots[featureIdx] = cell.empty() ? 0.0 : std::stod(cell);
        ++featureIdx;
    }

    if (featureIdx != kVectorDim) {
        throw std::runtime_error("MNIST row does not contain " + std::to_string(kFeatureDim) + " features");
    }

    return row;
}

std::vector<SampleRow> LoadMnistSamples(const std::string& path) {
    std::ifstream input(path);
    if (!input.is_open()) {
        throw std::runtime_error("Unable to open MNIST file: " + path);
    }

    std::vector<SampleRow> samples;
    std::string line;

    if (!std::getline(input, line)) {
        throw std::runtime_error("MNIST file is empty: " + path);
    }

    while (std::getline(input, line)) {
        if (line.empty()) {
            continue;
        }
        samples.emplace_back(ParseMnistLine(line));
    }

    return samples;
}

Ciphertext<DCRTPoly> EvaluateInnerProduct(const CryptoContext<DCRTPoly>& cc,
                                          const Ciphertext<DCRTPoly>& lhs,
                                          const Ciphertext<DCRTPoly>& rhs,
                                          std::size_t usedSlots) {
    Ciphertext<DCRTPoly> accumulator = cc->EvalMult(lhs, rhs);
    cc->RescaleInPlace(accumulator);

    for (std::size_t step = 1; step < usedSlots; step <<= 1) {
        auto rotated = cc->EvalRotate(accumulator, static_cast<int32_t>(step));
        accumulator = cc->EvalAdd(accumulator, rotated);
    }

    return accumulator;
}

} // namespace

int main(int argc, char** argv) {
    try {
        const std::string mnistPath = (argc > 1) ? argv[1] : kDefaultMnistPath;
        const std::string omegaPath = (argc > 2) ? argv[2] : kDefaultOmegaPath;

        std::cout << "Loading MNIST samples from " << mnistPath << std::endl;
        auto samples = LoadMnistSamples(mnistPath);
        if (samples.empty()) {
            std::cerr << "MNIST dataset is empty." << std::endl;
            return 1;
        }
        std::cout << "Loaded " << samples.size() << " labeled rows" << std::endl;

        std::cout << "Loading omega vector from " << omegaPath << std::endl;
        const auto omegaSlots = LoadOmegaSlots(omegaPath);
        std::cout << "Omega vector length (incl. bias): " << omegaSlots.size() << std::endl;

        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetMultiplicativeDepth(22);
        parameters.SetScalingModSize(49);
        parameters.SetSecurityLevel(HEStd_128_classic);
        parameters.SetFirstModSize(50);
        parameters.SetNumLargeDigits(4);
        parameters.SetBatchSize(kBatchSize);

        std::cout << "Generating crypto context..." << std::endl;
        CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);
        std::cout << "Ring dimension: " << cc->GetRingDimension() << std::endl;

        std::cout << "Key generation..." << std::endl;
        auto keys = cc->KeyGen();
        cc->EvalMultKeyGen(keys.secretKey);
        cc->EvalRotateKeyGen(keys.secretKey, BuildRotationKeySteps(kVectorDim));
        std::cout << "Keys ready. Starting encryptions." << std::endl;

        Plaintext omegaPlain = cc->MakeCKKSPackedPlaintext(omegaSlots);
        Ciphertext<DCRTPoly> omegaCipher = cc->Encrypt(keys.publicKey, omegaPlain);

        std::size_t correct = 0;
        const std::size_t total = samples.size();
        const std::size_t evalSamples = std::min<std::size_t>(total, 50);
        if (evalSamples < total) {
            std::cout << "Processing only the first " << evalSamples
                      << " samples for faster turnaround (out of " << total << ")" << std::endl;
        }

        const auto evalStart = std::chrono::steady_clock::now();

        std::size_t processed = 0;
        for (std::size_t idx = 0; idx < evalSamples; ++idx) {
            const auto& sample = samples[idx];
            Plaintext samplePlain = cc->MakeCKKSPackedPlaintext(sample.slots);
            Ciphertext<DCRTPoly> sampleCipher = cc->Encrypt(keys.publicKey, samplePlain);

            auto innerCipher = EvaluateInnerProduct(cc, sampleCipher, omegaCipher, kVectorDim);

            Plaintext innerPlain;
            cc->Decrypt(keys.secretKey, innerCipher, &innerPlain);
            innerPlain->SetLength(1);
            const auto& decoded = innerPlain->GetCKKSPackedValue();
            const double score = decoded.empty() ? 0.0 : decoded[0].real();
            const int prediction = (score >= 0.0) ? 1 : 0;
            if (prediction == sample.label) {
                ++correct;
            }

            ++processed;
            if ((processed % 10u) == 0u || processed == evalSamples) {
                std::cout << "Processed " << processed << "/" << evalSamples
                          << " samples "
                          << std::endl;
            }
        }

        const auto evalEnd = std::chrono::steady_clock::now();
        const auto totalUs = std::chrono::duration_cast<std::chrono::microseconds>(evalEnd - evalStart).count();


        const double avgUs = static_cast<double>(totalUs) / static_cast<double>(processed);

        std::cout << "MNIST samples available: " << total << std::endl;
        std::cout << "Samples evaluated this run: " << processed << std::endl;
        std::cout << "Vector dimension (with bias): " << kVectorDim << std::endl;
        std::cout << "Total execution time (ms): " << std::fixed << std::setprecision(2)
                  << static_cast<double>(totalUs) / 1000.0 << std::endl;
        std::cout << "Average time per inner product (us): " << std::fixed << std::setprecision(2) << avgUs
                  << std::endl;

        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    }
}
