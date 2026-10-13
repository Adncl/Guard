#include "AnalysisCore.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Operator.h"
#include "llvm/Support/ErrorHandling.h"
#include <filesystem>
#include <fstream>
#include <map>
#include <set>
#include <deque>
using namespace llvm;
namespace pg {
std::string env(const char *key, const std::string &fallback) {
  const char *p = std::getenv(key); return p && *p ? p : fallback;
}
void write(const std::string &path, const json &data) {
  auto parent = std::filesystem::path(path).parent_path();
  if (!parent.empty()) std::filesystem::create_directories(parent);
  std::ofstream out(path); if (!out) report_fatal_error("Cannot write analysis output");
  out << data.dump(2) << '\n';
}
std::string sourceFile(const DISubprogram *sp) {
  if (!sp) return "";
  std::filesystem::path p(sp->getFilename().str());
  if (p.is_relative()) p = std::filesystem::path(sp->getDirectory().str()) / p;
  return p.lexically_normal().string();
}
json analyze(Module &M) {
  json out = {{"schema_version",1},{"functions",json::object()},
              {"nodes",json::array()},{"edges",json::array()}};
  std::map<Value*,unsigned> ids;
  std::map<Function*,std::set<Function*>> calls, callers;
  std::map<CallBase*,std::set<Function*>> targets;
  std::map<std::string,std::set<std::string>> wpa;
  const std::string wpaPath = env("WPA_REPORT_FILE");
  const bool requireSVF = env("PROTOCOLGUARD_REQUIRE_SVF", "0") == "1";
  if (requireSVF && wpaPath.empty())
    report_fatal_error("PROTOCOLGUARD_REQUIRE_SVF=1 but WPA_REPORT_FILE is unset");
  std::ifstream fp(wpaPath); std::string loc, name;
  if (requireSVF && !fp)
    report_fatal_error(Twine("Cannot open the SVF indirect-call report: ") + wpaPath);
  while (fp >> loc >> name) wpa[loc].insert(name);
  if (requireSVF && wpa.empty())
    report_fatal_error(Twine("The SVF indirect-call report is empty: ") + wpaPath);
  std::map<std::string,std::vector<unsigned>> memory;
  std::set<std::pair<unsigned,unsigned>> edges;
  std::set<Function*> receiving;
  auto addNode = [&](Value *v, Function *f, unsigned line, const std::string &op) {
    unsigned id = out["nodes"].size(); ids[v] = id;
    out["nodes"].push_back({{"id",id},{"function",f->getName().str()},
      {"line",line},{"name",v->getName().str()},{"op",op}});
  };
  for (Function &f : M) if (!f.isDeclaration()) {
    json j = {{"name",f.getName().str()}, {"file",sourceFile(f.getSubprogram())},
      {"start",f.getSubprogram()?f.getSubprogram()->getLine():0}, {"end",0},
      {"calls",json::array()}, {"variables",json::object()}, {"arguments",json::array()}};
    for (auto &a : f.args()) { addNode(&a,&f,0,"argument"); j["arguments"].push_back(ids[&a]); }
    for (Instruction &i : instructions(f)) {
      unsigned line = i.getDebugLoc()?i.getDebugLoc().getLine():0;
      addNode(&i,&f,line,i.getOpcodeName());
      j["end"] = std::max(j["end"].get<unsigned>(),line);
    }
    out["functions"][f.getName().str()] = j;
  }
  auto edge = [&](Value *a, Value *b) {
    if (ids.count(a) && ids.count(b) && a != b) edges.insert({ids[a],ids[b]});
  };
  // Field-sensitive memory keys. Dynamic offsets deliberately collapse to an
  // object; typed structure fields also share a key across aliasing pointers.
  auto memkeys = [&](Value *p) {
    std::vector<std::string> keys;
    Value *base = getUnderlyingObject(p);
    if (ids.count(base)) keys.push_back("object:"+std::to_string(ids[base]));
    if (auto *g = dyn_cast<GEPOperator>(p->stripPointerCasts())) {
      std::string type; raw_string_ostream os(type); g->getSourceElementType()->print(os);
      std::string key = os.str();
      for (auto it=g->idx_begin(); it!=g->idx_end(); ++it)
        key += ":" + (isa<ConstantInt>(it->get()) ? std::to_string(cast<ConstantInt>(it->get())->getSExtValue()) : "*");
      keys.push_back("field:"+key);
      // Do not collapse distinct constant fields into the same object.
      if (keys.size()>1) keys.erase(keys.begin());
    }
    if (auto *g = dyn_cast<GlobalVariable>(base)) keys.push_back("global:"+g->getName().str());
    return keys;
  };
  for (Function &f : M) if (!f.isDeclaration()) for (Instruction &i : instructions(f)) {
    for (Use &operand : i.operands()) edge(operand.get(),&i);
    if (auto *dbg = dyn_cast<DbgVariableIntrinsic>(&i)) {
      auto &v = out["functions"][f.getName().str()]["variables"][dbg->getVariable()->getName().str()];
      if (v.is_null()) v=json::array();
      for (Value *x : dbg->location_ops()) if (ids.count(x)) v.push_back(ids[x]);
    }
    Value *ptr = nullptr;
    if (auto *s = dyn_cast<StoreInst>(&i)) {ptr=s->getPointerOperand(); edge(s->getValueOperand(),ptr);}
    if (auto *l = dyn_cast<LoadInst>(&i)) ptr=l->getPointerOperand();
    if (ptr) for (auto &k : memkeys(ptr)) memory[k].push_back(ids[&i]);
    auto *cb = dyn_cast<CallBase>(&i); if (!cb || isa<DbgInfoIntrinsic>(i)) continue;
    if (auto *direct = dyn_cast<Function>(cb->getCalledOperand()->stripPointerCasts())) targets[cb].insert(direct);
    else {
      std::string at = sourceFile(f.getSubprogram())+":"+std::to_string(i.getDebugLoc()?i.getDebugLoc().getLine():0);
      for (auto &kv : wpa) if (kv.first==at || std::filesystem::path(kv.first).filename()==std::filesystem::path(at).filename())
        for (auto &fn : kv.second) if (auto *candidate=M.getFunction(fn)) targets[cb].insert(candidate);
    }
    for (Function *callee : targets[cb]) {
      calls[&f].insert(callee); callers[callee].insert(&f);
      if (callee->getName()=="recv" || callee->getName()=="recvfrom" || callee->getName()=="recvmsg" || callee->getName()=="read" || callee->getName()=="SSL_read") receiving.insert(&f);
      if (!callee->isDeclaration()) {
        for (unsigned a=0; a<std::min<unsigned>(cb->arg_size(),callee->arg_size()); ++a) {
          edge(cb->getArgOperand(a),callee->getArg(a));
          if (cb->getArgOperand(a)->getType()->isPointerTy()) edge(callee->getArg(a),cb->getArgOperand(a));
        }
        for (auto &ci : instructions(callee)) if (auto *ret=dyn_cast<ReturnInst>(&ci)) if (ret->getReturnValue()) edge(ret->getReturnValue(),cb);
      } else if (callee->getName().contains("memcpy") || callee->getName().contains("memmove") || callee->getName()=="strcpy" || callee->getName()=="snprintf") {
        if (cb->arg_size()) for (unsigned a=1;a<cb->arg_size();++a) edge(cb->getArgOperand(a),cb->getArgOperand(0));
      }
    }
  }
  // Connect stores to loads of an aliasing abstract memory location. Keeping
  // all reaching stores is conservative across loops and unknown call order.
  for (auto &kv : memory) {
    std::vector<unsigned> stores,loads;
    for (unsigned id:kv.second) (out["nodes"][id]["op"]=="store"?stores:loads).push_back(id);
    for (unsigned s:stores) for (unsigned l:loads) if(s!=l) edges.insert({s,l});
  }
  std::set<Function*> roots=receiving; std::deque<Function*> work(receiving.begin(),receiving.end());
  // Callback dispatch can detach the receive buffer from a lexical caller.
  // Preserve ancestors and their reachable subgraphs as a conservative bound.
  while(!work.empty()) {auto *f=work.front();work.pop_front();for(auto *p:callers[f])if(roots.insert(p).second)work.push_back(p);}
  std::set<Function*> message=roots;work=std::deque<Function*>(roots.begin(),roots.end());
  while(!work.empty()){auto *f=work.front();work.pop_front();for(auto *c:calls[f])if(!c->isDeclaration()&&message.insert(c).second)work.push_back(c);}
  out["message_roots"]=json::array();
  for (auto *f:roots) if(callers[f].empty()) out["message_roots"].push_back(f->getName().str());
  for (auto &kv:out["functions"].items()) {
    auto *f=M.getFunction(kv.key());
    for (auto *c:calls[f]) kv.value()["calls"].push_back(c->getName().str());
    kv.value()["message_related"]=message.count(f)!=0;
  }
  for(auto &e:edges) out["edges"].push_back({e.first,e.second});
  out["indirect_call_method"] = wpa.empty()
      ? "unconfigured (no SVF report)"
      : "SVF-2.9 Andersen wave propagation (-print-fp)";
  return out;
}
}
