#include "openfhe.h"

#include <algorithm>
#include <chrono>
#include <complex>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>

using namespace lbcrypto;

namespace {

constexpr std::size_t kBatchSize = 256;                    // CKKS packing slots we plan to use
const std::string kDefaultMnistPath = "/home/wzh/openfhe-development/src/pke/examples/data/MNIST_test.txt";
const std::string kDefaultOmegaPath = "/home/wzh/openfhe-development/src/pke/examples/data/omega.txt";

struct OperationStats {
    uint64_t count = 0;
    long long totalMicros = 0;

    void Record(long long micros) {
        ++count;
        totalMicros += micros;
    }

    double AverageMicros() const {
        return count == 0 ? 0.0 : static_cast<double>(totalMicros) / static_cast<double>(count);
    }
};

struct ProfilingSummary {
    OperationStats encrypt;
    OperationStats decrypt;
    OperationStats evalMult;
    OperationStats evalRotate;
    OperationStats evalAdd;
    OperationStats rescale;
};

struct SecureMlDataset {
    std::vector<std::vector<double>> rows; // label already folded into features
    std::size_t factorDim = 0;
};

template <typename Func>
auto MeasureAndRecord(OperationStats& stats, Func&& func) {
    const auto start = std::chrono::high_resolution_clock::now();
    if constexpr (std::is_void_v<std::invoke_result_t<Func&>>) {
        func();
        const auto end = std::chrono::high_resolution_clock::now();
        stats.Record(std::chrono::duration_cast<std::chrono::microseconds>(end - start).count());
    }
    else {
        auto result = func();
        const auto end = std::chrono::high_resolution_clock::now();
        stats.Record(std::chrono::duration_cast<std::chrono::microseconds>(end - start).count());
        return result;
    }
}

std::vector<int32_t> BuildRotationKeySteps(std::size_t usedSlots) {
    std::vector<int32_t> steps;
    for (std::size_t step = 1; step < usedSlots; step <<= 1) {
        steps.push_back(static_cast<int32_t>(step));
    }
    return steps;
}

std::vector<double> ParseNumericLine(const std::string& line, std::size_t expectedCols) {
    std::vector<double> row;
    row.reserve(expectedCols);
    std::stringstream ss(line);
    std::string cell;
    while (std::getline(ss, cell, ',')) {
        if (cell.empty()) {
            row.push_back(0.0);
        }
        else {
            row.push_back(std::stod(cell));
        }
    }
    if (!row.empty() && row.size() != expectedCols) {
        throw std::runtime_error("Unexpected column count in MNIST row: expected " +
                                 std::to_string(expectedCols) + ", got " + std::to_string(row.size()));
    }
    return row;
}

void NormalizeColumns(std::vector<std::vector<double>>& rows) {
    if (rows.empty()) {
        return;
    }
    const std::size_t cols = rows.front().size();
    for (std::size_t col = 0; col < cols; ++col) {
        double maxAbs = 0.0;
        for (const auto& row : rows) {
            maxAbs = std::max(maxAbs, std::abs(row[col]));
        }
        if (maxAbs > 1e-10) {
            for (auto& row : rows) {
                row[col] /= maxAbs;
            }
        }
    }
}

SecureMlDataset LoadSecureMlDataset(const std::string& path) {
    std::ifstream input(path);
    if (!input.is_open()) {
        throw std::runtime_error("Unable to open MNIST file: " + path);
    }

    std::string header;
    if (!std::getline(input, header)) {
        throw std::runtime_error("MNIST file is empty: " + path);
    }

    const std::size_t factorDim = std::count(header.begin(), header.end(), ',') + 1;
    if (factorDim == 0) {
        throw std::runtime_error("Could not determine MNIST feature dimension from header");
    }

    std::vector<std::vector<double>> raw;
    std::string line;
    while (std::getline(input, line)) {
        if (line.empty()) {
            continue;
        }
        auto parsed = ParseNumericLine(line, factorDim);
        if (!parsed.empty()) {
            raw.emplace_back(std::move(parsed));
        }
    }

    if (raw.empty()) {
        throw std::runtime_error("No MNIST samples found in " + path);
    }

    SecureMlDataset dataset;
    dataset.factorDim = factorDim;
    dataset.rows.resize(raw.size(), std::vector<double>(factorDim, 0.0));

    for (std::size_t j = 0; j < raw.size(); ++j) {
        const double label = raw[j][0];
        const double labelSign = 2.0 * label - 1.0; // map {0,1} -> {-1, +1}
        dataset.rows[j][0] = labelSign;
        for (std::size_t i = 1; i < factorDim; ++i) {
            dataset.rows[j][i] = labelSign * raw[j][i];
        }
    }

    NormalizeColumns(dataset.rows);
    return dataset;
}

std::vector<double> PadSlots(const std::vector<double>& values, std::size_t slotCount) {
    std::vector<double> slots(slotCount, 0.0);
    const std::size_t copyCount = std::min(values.size(), slotCount);
    std::copy(values.begin(), values.begin() + copyCount, slots.begin());
    return slots;
}

std::vector<double> LoadOmegaValues(const std::string& path, std::size_t expectedDim) {
    std::ifstream input(path);
    if (!input.is_open()) {
        throw std::runtime_error("Unable to open omega file: " + path);
    }

    std::vector<double> raw;
    double value = 0.0;
    while (input >> value) {
        raw.push_back(value);
    }

    if (raw.size() < expectedDim) {
        throw std::runtime_error("omega length mismatch: expected at least " + std::to_string(expectedDim) +
                                 ", got " + std::to_string(raw.size()));
    }

    raw.resize(expectedDim);
    return raw;
}

Ciphertext<DCRTPoly> EvaluateInnerProduct(const CryptoContext<DCRTPoly>& cc,
                                          const Ciphertext<DCRTPoly>& lhs,
                                          const Ciphertext<DCRTPoly>& rhs,
                                          std::size_t usedSlots,
                                          ProfilingSummary& profiling) {
    Ciphertext<DCRTPoly> accumulator =
        MeasureAndRecord(profiling.evalMult, [&] { return cc->EvalMult(lhs, rhs); });
    MeasureAndRecord(profiling.rescale, [&] { cc->RescaleInPlace(accumulator); });

    for (std::size_t step = 1; step < usedSlots; step <<= 1) {
        auto rotated = MeasureAndRecord(profiling.evalRotate, [&] {
            return cc->EvalRotate(accumulator, static_cast<int32_t>(step));
        });
        accumulator = MeasureAndRecord(profiling.evalAdd, [&] {
            return cc->EvalAdd(accumulator, rotated);
        });
    }

    return accumulator;
}

} // namespace

int main(int argc, char** argv) {
    try {
        const std::string mnistPath = (argc > 1) ? argv[1] : kDefaultMnistPath;
        const std::string omegaPath = (argc > 2) ? argv[2] : kDefaultOmegaPath;

        std::cout << "Loading MNIST samples from " << mnistPath << std::endl;
        auto dataset = LoadSecureMlDataset(mnistPath);
        if (dataset.rows.empty()) {
            std::cerr << "MNIST dataset is empty." << std::endl;
            return 1;
        }
        std::cout << "Loaded " << dataset.rows.size() << " labeled rows" << std::endl;
        std::cout << "SecureML factor dimension (label folded into features): " << dataset.factorDim << std::endl;
        if (dataset.factorDim > kBatchSize) {
            std::cerr << "Factor dimension " << dataset.factorDim << " exceeds batch size " << kBatchSize << std::endl;
            return 1;
        }

        std::cout << "Loading omega vector from " << omegaPath << std::endl;
        const auto omegaValues = LoadOmegaValues(omegaPath, dataset.factorDim);
        const auto omegaSlots = PadSlots(omegaValues, kBatchSize);
        std::cout << "Omega vector length (used): " << omegaValues.size() << std::endl;

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
        cc->EvalRotateKeyGen(keys.secretKey, BuildRotationKeySteps(dataset.factorDim));
        std::cout << "Keys ready. Starting encryptions." << std::endl;

        ProfilingSummary profiling;

        Plaintext omegaPlain = cc->MakeCKKSPackedPlaintext(omegaSlots);
        Ciphertext<DCRTPoly> omegaCipher = MeasureAndRecord(profiling.encrypt, [&] {
            return cc->Encrypt(keys.publicKey, omegaPlain);
        });

        std::size_t correct = 0;
        const std::size_t total = dataset.rows.size();
        const std::size_t evalSamples = std::min<std::size_t>(total, 50);
        if (evalSamples < total) {
            std::cout << "Processing only the first " << evalSamples
                      << " samples for faster turnaround (out of " << total << ")" << std::endl;
        }

        const auto evalStart = std::chrono::steady_clock::now();

        std::size_t processed = 0;
        for (std::size_t idx = 0; idx < evalSamples; ++idx) {
            const auto sampleSlots = PadSlots(dataset.rows[idx], kBatchSize);
            Plaintext samplePlain = cc->MakeCKKSPackedPlaintext(sampleSlots);
            Ciphertext<DCRTPoly> sampleCipher = MeasureAndRecord(profiling.encrypt, [&] {
                return cc->Encrypt(keys.publicKey, samplePlain);
            });

            auto innerCipher = EvaluateInnerProduct(cc, sampleCipher, omegaCipher, dataset.factorDim, profiling);

            Plaintext innerPlain;
            MeasureAndRecord(profiling.decrypt, [&] { cc->Decrypt(keys.secretKey, innerCipher, &innerPlain); });
            innerPlain->SetLength(1);
            const auto& decoded = innerPlain->GetCKKSPackedValue();
            const double score = decoded.empty() ? 0.0 : decoded[0].real();
            if (score >= 0.0) {
                ++correct;
            }

            ++processed;
            if ((processed % 10u) == 0u || processed == evalSamples) {
                std::cout << "Processed " << processed << "/" << evalSamples
                          << " samples (current accuracy: "
                          << std::fixed << std::setprecision(2)
                          << (static_cast<double>(correct) / processed) * 100.0 << "%)" << std::endl;
            }
        }

        const auto evalEnd = std::chrono::steady_clock::now();
        const auto totalUs = std::chrono::duration_cast<std::chrono::microseconds>(evalEnd - evalStart).count();

        const double accuracy = processed == 0 ? 0.0 : static_cast<double>(correct) / static_cast<double>(processed);
        const double avgUs = processed == 0 ? 0.0 : static_cast<double>(totalUs) / static_cast<double>(processed);

        std::cout << "MNIST samples available: " << total << std::endl;
        std::cout << "Samples evaluated this run: " << processed << std::endl;
        std::cout << "Vector dimension (SecureML): " << dataset.factorDim << std::endl;
        std::cout << "Total execution time (ms): " << std::fixed << std::setprecision(2)
                  << static_cast<double>(totalUs) / 1000.0 << std::endl;
        std::cout << "Average time per inner product (us): " << std::fixed << std::setprecision(2) << avgUs
                  << std::endl;
        std::cout << "Accuracy (sign check): " << std::fixed << std::setprecision(2)
                  << (accuracy * 100.0) << "% (" << correct << "/" << processed << ")" << std::endl;

        const auto printStats = [](const std::string& name, const OperationStats& stats) {
            std::cout << "  " << name << " -> count: " << stats.count << ", total (us): " << stats.totalMicros
                      << ", avg (us): " << std::fixed << std::setprecision(2) << stats.AverageMicros() << std::endl;
        };

        std::cout << "Operator statistics:" << std::endl;
        printStats("Encrypt", profiling.encrypt);
        printStats("Decrypt", profiling.decrypt);
        printStats("EvalMult", profiling.evalMult);
        printStats("Rescale", profiling.rescale);
        printStats("EvalRotate", profiling.evalRotate);
        printStats("EvalAdd", profiling.evalAdd);

        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    }
}
