#include "AnalysisCore.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include <filesystem>
#include <fstream>
#include <set>
using namespace llvm;
struct AssertPass : PassInfoMixin<AssertPass> {
 PreservedAnalyses run(Module &M,ModuleAnalysisManager &) {
  auto dir=pg::env("ASSERT_OUTPUT_DIR",".");std::filesystem::create_directories(dir);
  std::set<std::string> locations;
  for(auto &f:M) for(auto &i:instructions(f)) if(auto *call=dyn_cast<CallBase>(&i))
   if(auto *callee=call->getCalledFunction()) if(callee->getName()=="__assert_fail"||callee->getName()=="__assert_rtn"||callee->getName()=="_assert") {
    if(auto d=i.getDebugLoc()) locations.insert(pg::sourceFile(f.getSubprogram())+":"+std::to_string(d.getLine()));
   }
  // Both spellings are used by the released README/DFUZZ implementation.
  for(auto file:{"real.txt","reals.txt"}) {std::ofstream o(dir+"/"+file);for(auto &l:locations)o<<l<<'\n';}
  errs()<<"ProtocolGuard: "<<locations.size()<<" assertion targets\n";
  return PreservedAnalyses::all();
 }
};
extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo(){
 return {LLVM_PLUGIN_API_VERSION,"AssertPass",LLVM_VERSION_STRING,[](PassBuilder &PB){
 PB.registerPipelineParsingCallback([](StringRef n,ModulePassManager &pm,ArrayRef<PassBuilder::PipelineElement>){
 if(n!="assert-call-analysis")return false;pm.addPass(AssertPass());return true;});}};
}
