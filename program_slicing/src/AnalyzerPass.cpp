#include "AnalysisCore.h"
#include "Analyzer.h"
#include <filesystem>
#include <fstream>
using namespace llvm;
PreservedAnalyses AnalyzerPass::run(Module &M, ModuleAnalysisManager &) {
  auto data=pg::analyze(M); auto dir=pg::env("PROTOCOLGUARD_OUTPUT_DIR",".");
  pg::write(dir+"/analysis.json",data);
  std::ofstream cg(dir+"/packet_callgraph.txt"), args(dir+"/function_arg_summary.txt");
  for(auto &f:data["functions"].items()) {
    args<<f.key()<<" "<<f.value()["arguments"].size()<<"\n";
    if(f.value()["message_related"].get<bool>()) for(auto &c:f.value()["calls"]) cg<<f.key()<<" -> "<<c.get<std::string>()<<"\n";
  }
  return PreservedAnalyses::all();
}
extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo() {
 return {LLVM_PLUGIN_API_VERSION,"AnalyzerPass",LLVM_VERSION_STRING,[](PassBuilder &PB){
 PB.registerPipelineParsingCallback([](StringRef n,ModulePassManager &pm,ArrayRef<PassBuilder::PipelineElement>){
 if(n!="analyzer-pass")return false;pm.addPass(AnalyzerPass());return true;});}};
}
