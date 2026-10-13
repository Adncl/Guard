#include "AnalysisCore.h"
#include "llvm/Support/Program.h"
#include <filesystem>
using namespace llvm;
struct MatchPass : PassInfoMixin<MatchPass> {
 std::string config;
 explicit MatchPass(std::string path):config(std::move(path)){}
 PreservedAnalyses run(Module &M,ModuleAnalysisManager &) {
   auto data=pg::analyze(M);
   std::string path=pg::env("PROTOCOLGUARD_OUTPUT_DIR",".")+"/analysis.json";
   pg::write(path,data);
   auto python=sys::findProgramByName(pg::env("PYTHON","python3"));
   if(!python)report_fatal_error("Python executable not found");
   SmallVector<StringRef,12> args={*python,"-m","protocolguard.slicing","--config",config,"--analysis",path};
   int code=sys::ExecuteAndWait(*python,args);
   if(code!=0)report_fatal_error("ProtocolGuard slicing failed; see Python error above");
   return PreservedAnalyses::all();
 }
};
extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo(){
 return {LLVM_PLUGIN_API_VERSION,"MatchPass",LLVM_VERSION_STRING,[](PassBuilder &PB){
 PB.registerPipelineParsingCallback([](StringRef n,ModulePassManager &pm,ArrayRef<PassBuilder::PipelineElement>){
 if(!n.consume_front("match-pass<config=")||!n.consume_back(">"))return false;
 pm.addPass(MatchPass(n.str()));return true;});}};
}
