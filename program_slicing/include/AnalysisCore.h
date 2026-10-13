#pragma once
#include "llvm/IR/Module.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include <nlohmann/json.hpp>
#include <string>
namespace pg {
using json = nlohmann::json;
json analyze(llvm::Module &M);
std::string env(const char *name, const std::string &fallback = "");
void write(const std::string &path, const json &data);
std::string sourceFile(const llvm::DISubprogram *SP);
}
