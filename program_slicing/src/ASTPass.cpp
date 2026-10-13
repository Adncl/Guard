#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendPluginRegistry.h"
#include "clang/Lex/Lexer.h"
#include <nlohmann/json.hpp>
#include <filesystem>
#include <fstream>
using namespace clang;
using json=nlohmann::json;
class Visitor : public RecursiveASTVisitor<Visitor> {
 ASTContext &ctx;
 unsigned line(SourceLocation l){auto &sm=ctx.getSourceManager();return sm.getExpansionLineNumber(l);}
 json range(SourceRange r){return {{"start",line(r.getBegin())},{"end",line(r.getEnd())}};}
 json controls(Stmt *s) {
  json nodes=json::array(); if(!s)return nodes;
  json node; Stmt *cond=nullptr,*body=nullptr;
  if(auto *p=dyn_cast<IfStmt>(s)){node["type"]="if";cond=p->getCond();body=p->getThen();if(p->getElse())node["location"]["if_else"]=range(p->getElse()->getSourceRange());}
  else if(auto *p=dyn_cast<WhileStmt>(s)){node["type"]="while";cond=p->getCond();body=p->getBody();}
  else if(auto *p=dyn_cast<ForStmt>(s)){node["type"]="for";cond=p->getCond();body=p->getBody();}
  else if(auto *p=dyn_cast<SwitchStmt>(s)){node["type"]="switch";cond=p->getCond();body=p->getBody();}
  else if(auto *p=dyn_cast<DoStmt>(s)){node["type"]="do";cond=p->getCond();body=p->getBody();}
  json children=json::array(); for(auto *c:s->children()) for(auto &n:controls(c))children.push_back(n);
  if(!node.is_null()) {
   node["location"]["full"]=range(s->getSourceRange());
   node["location"]["condition"]=cond?range(cond->getSourceRange()):range(s->getSourceRange());
   node["location"]["body"]=body?range(body->getSourceRange()):range(s->getSourceRange());
   node["children"]=children;nodes.push_back(node);
  }else nodes=children;
  return nodes;
 }
public:
 json functions=json::array();
 explicit Visitor(ASTContext &c):ctx(c){}
 bool VisitFunctionDecl(FunctionDecl *f){
  if(!f->doesThisDeclarationHaveABody()||!ctx.getSourceManager().isWrittenInMainFile(f->getLocation()))return true;
  functions.push_back({{"name",f->getNameAsString()},{"overall",range(f->getSourceRange())},
    {"body",range(f->getBody()->getSourceRange())},{"control_flow",controls(f->getBody())}});
  return true;
 }
};
class Consumer : public ASTConsumer {
public:
 void HandleTranslationUnit(ASTContext &c)override{
  Visitor v(c);v.TraverseDecl(c.getTranslationUnitDecl());
  const auto *entry=c.getSourceManager().getFileEntryForID(c.getSourceManager().getMainFileID());if(!entry)return;
  std::filesystem::path p(entry->getName().str());
  std::ofstream out(p.parent_path()/(".cf_"+p.stem().string()+".json"));
  out<<json({{"source_file",p.string()},{"functions",v.functions}}).dump(2)<<'\n';
 }
};
class Action : public PluginASTAction {
 std::unique_ptr<ASTConsumer>CreateASTConsumer(CompilerInstance &,llvm::StringRef)override{return std::make_unique<Consumer>();}
 bool ParseArgs(const CompilerInstance &,const std::vector<std::string>&)override{return true;}
};
static FrontendPluginRegistry::Add<Action> X("cf-analyzer","ProtocolGuard control-flow source ranges");
