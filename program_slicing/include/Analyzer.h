#ifndef LLVM_PASS_ANALYZER_H
#define LLVM_PASS_ANALYZER_H

#include "llvm/IR/PassManager.h"

namespace llvm {
class AnalyzerPass : public PassInfoMixin<AnalyzerPass> {
public:
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);

  static bool isRequired() { return true; }
};
} // namespace llvm

#endif // LLVM_PASS_ANALYZER_H
