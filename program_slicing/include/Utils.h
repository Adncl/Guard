#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/Support/Error.h"
#include "llvm/IR/DebugInfo.h"         
#include "llvm/IR/DebugInfoMetadata.h" 
#include "llvm/IR/Instructions.h"
#include <set>
#include <map>
#include <fstream>
#include <filesystem>
#include <unordered_set>
#include <string>
#include <curl/curl.h>
#include <sqlite3.h>
#include <nlohmann/json.hpp>
#include "toml.hpp"
using nlohmann::json;
using std::endl;
using std::string;
#include <thread>   
#include <chrono>   

using namespace llvm;


#define LLM_GENERAL_MESSAGE_RELEVANT 0             
#define LLM_MESSAGE_HANDLER_RELEVANT 1             
#define LLM_REQUEST_FIELD_VARIABLE 2               
#define LLM_FIELD_VARIABLE 3                       
#define LLM_FUNCTION_RELEVANT 4                    
#define LLM_SENDING_FUNCTION_RELEVANT 5            
#define LLM_BACKTRACE_SENDING_FUNCTION_RELEVANT 6  
#define LLM_COMPLETE_CODE 7                        
#define LLM_OTHER_ANALYSIS 8                       

extern sqlite3* sqlite_db;

// Type Definitions

struct GlobalConfig {
  // WPS
  static string WPA_PATH;

  // LLM 
  static string LLM_API_PLATFORM;
  static string LLM_MODEL_SELECTED;
  static string LLM_MODEL_DEEPSEEK_V3;
  static string LLM_MODEL_DEEPSEEK_R1;
  static int LLM_QUERY_REPEAT_TIMES;
  static int LLM_QUERY_MAX_ATTEMPTS;
  static int LLM_MULTI_THREAD;

  // SQLITE
  static string SQLITE_DB_PATH;

  // Project Under Test
  static string PROTOCOL_NAME;
  static string PROJECT_NAME;
  static string PACKET_CALLGRAPH_PATH;
  static string RULE_PATH;
  static string FUNCTION_ARG_PATH;
  static string ORIGINAL_LLVM_IR_PATH;
  static string PROTOCOL_VERSION;
  static int MULTIPLE_PROTOCOL_MODE;

  // Debug
  static int CODE_SLIECE_REPLACE_MODE;
  static int LOG_PRINT;

  // Config
  static std::vector<std::string> PACKET_TYPES;
};

struct Rule {
  string rule_desc;
  string req_type;
  std::vector<string> req_fields;
  string res_type;
  std::vector<string> res_fields;
  std::vector<string> protocol_states;
};


struct GepObj {
  Type *type;
  int pos_base;
  int pos_offset;
  bool IsInitialized;
  
  std::vector<GepObj> baseGepObj;

  GepObj(): type(nullptr), pos_base(-1), pos_offset(-1), IsInitialized(false) {}

  bool operator==(const GepObj &other) const {
      if (type != other.type || pos_base != other.pos_base || pos_offset != other.pos_offset)
          return false;
      if (baseGepObj.size() != other.baseGepObj.size())
          return false;
      for (size_t i = 0; i < baseGepObj.size(); ++i) {
          if (!(baseGepObj[i] == other.baseGepObj[i]))
              return false;
      }
      return true;
  }
};

// AST Control Node
struct LineRange {
    int start;
    int end;
    LineRange(int s = 0, int e = 0) : start(s), end(e) {}

    std::vector<int> toVector() const {
        std::vector<int> result;
        int begin = std::min(start, end);
        int finish = std::max(start, end);
        for (int i = begin; i <= finish; ++i) {
            result.push_back(i);
        }
        return result;
    }

    bool isEmpty() const {
        return start == 0 && end == 0;
    }
};

struct LocationInfo {
    LineRange condition;
    LineRange body;
    LineRange full;
    LineRange if_else;

    std::vector<int> caseVec;
    std::vector<int> breakVec;
    int default_line;

    LocationInfo(LineRange c = {}, LineRange b = {}, LineRange f = {}, LineRange i = {})
        : condition(c), body(b), full(f), if_else(i) {}
};

enum AST_NODE_TYPE {
    AST_NODE_TYPE_IF = 1,
    AST_NODE_TYPE_WHILE = 2,
    AST_NODE_TYPE_FOR = 3,
    AST_NODE_TYPE_SWITCH = 4,
    AST_NODE_TYPE_UNKNOWN = 5
};

struct ControlFlowNode {
    enum AST_NODE_TYPE type; // "IF", "WHILE" 
    LocationInfo location;

    int depth;
    std::vector<std::shared_ptr<ControlFlowNode>> children;
    ControlFlowNode(enum AST_NODE_TYPE t, LocationInfo loc, int d)
        : type(t), location(loc), depth(d) {}
};

struct LabelInfo {
    std::string name;  
    LineRange range;   

    LabelInfo(std::string n = "", LineRange r = {}) : name(n), range(r) {}
};

struct FunctionControlFlow {
    std::string name;  
    int overall_start, overall_end;
    int body_start, body_end;
    std::string source_file;  
    std::vector<std::shared_ptr<ControlFlowNode>> control_flow; 
    std::unordered_map<int, std::vector<ControlFlowNode*>> line_to_nodes;  
    std::vector<LabelInfo> labels;  
    std::unordered_map<int, std::vector<ControlFlowNode*>> line_to_parent_nodes;  

    static bool isLineInRange(int line, const LineRange& range) {
        return line >= range.start && line <= range.end;
    }

    std::vector<ControlFlowNode*> getWrappingNodes(int line) const {
        std::vector<ControlFlowNode*> nodes;
        auto it = line_to_nodes.find(line);
        if (it != line_to_nodes.end()) {
            nodes = it->second;
        }
        return nodes;
    }

    std::vector<LineRange> getWrappingConditions(int line) const {
        std::vector<LineRange> conditions;
        auto it = line_to_nodes.find(line);
        if (it != line_to_nodes.end()) {
            for (const auto* node : it->second) {
                conditions.push_back(node->location.condition);
            }
        }
        return conditions;
    }

    std::vector<LineRange> getWrappingBodies(int line) const {
        std::vector<LineRange> conditions;
        auto it = line_to_nodes.find(line);
        if (it != line_to_nodes.end()) {
            for (const auto* node : it->second) {
                conditions.push_back(node->location.body);
            }
        }
        return conditions;
    }

    std::vector<int> getWrappingSwitchControlFlowNode(int line) const {
        std::vector<int> result;

        if (line_to_nodes.find(line) != line_to_nodes.end()) {

            std::vector<ControlFlowNode*> cfNodesVec = line_to_nodes.at(line);
            
            for (auto cfNode : cfNodesVec) {
                if (cfNode->type != AST_NODE_TYPE_SWITCH) continue;

                const LocationInfo& switchLoc = cfNode->location;
                std::vector<int> entries = switchLoc.caseVec;
                
                if (switchLoc.default_line != -1) {
                    entries.push_back(switchLoc.default_line);
                }
                if (entries.empty()) continue;

                int active_entry = -1;
                for (int entry : entries) {
                    if (entry <= line) {
                        active_entry = entry; 
                    } else {
                        break; 
                    }
                }
                if (active_entry == -1) continue;

                int entry_end = switchLoc.full.end;
                for (int entry : entries) {
                    if (entry > active_entry) {
                        entry_end = entry - 1; 
                        break;
                    }
                }
                
                if (line < active_entry || line > entry_end) continue;

                std::vector<int> matched_breaks;
                for (int br : switchLoc.breakVec) {
                    if (br >= active_entry && br <= entry_end) {
                        matched_breaks.push_back(br);
                    }
                }
                result.push_back(active_entry); 

                for (int br : switchLoc.breakVec) {
                    if (br >= active_entry && br <= entry_end) {
                        result.push_back(br);
                    }
                }
            }
        }
        return result;
    }
};

class ControlFlowManager {
public:
    static ControlFlowManager& getInstance() {
        static ControlFlowManager instance;
        return instance;
    }

    std::string getJsonFilePath(llvm::Function* F) {
        std::string source_file;
    
        if (auto *SP = F->getSubprogram()) {       
            if (auto *File = SP->getFile()) {      
                source_file = File->getDirectory().str() + "/" + File->getFilename().str();
            }
        }
        
        if (source_file.empty()) {
            errs() << "Warning: No source file found for function " << F->getName() << "\n";
            return "";
        }

        std::filesystem::path source_path(source_file);
        std::filesystem::path json_path = source_path.parent_path() / (".cf_" + source_path.stem().string() + ".json");
        
        // errs() << "getJsonFilePath: " << F->getName() << "\t" << source_file << "\n";
        return json_path.string();
    }

    int getFunctionEndLine(llvm::Function* F, const std::string& json_file_path) {
        auto *SP = F->getSubprogram();
        if (!SP) {
            errs() << "Error: No DISubprogram found for function " << F->getName() << "\n";
            return -1;
        }

        int FuncStartLine = SP->getLine();

        std::ifstream fs(json_file_path);
        if (!fs.is_open()) {
            errs() << "Error: Failed to open JSON file '" << json_file_path << "'\n";
            return -1;
        }

        json data = json::parse(fs, nullptr, false);
        if (data.is_discarded()) {
            errs() << "Error: Failed to parse JSON file '" << json_file_path << "'\n";
            return -1;
        }

        for (auto& func : data["functions"]) {
            if (SP->getName() == F->getName()) {
                if (func["name"] == F->getName().str()) {
                    int overall_start = func["overall"]["start"];
                    int body_start = func["body"]["start"];

                    if (overall_start <= FuncStartLine && FuncStartLine <= body_start) {
                        return func["overall"]["end"];
                    }
                }
            } else {
                if (func["name"] == SP->getName().str()) {
                    if (func["overall"]["start"] == FuncStartLine) {
                        return func["overall"]["end"];
                    } else if (func["body"]["start"] == FuncStartLine) {
                        int overall_end = func["overall"]["end"];
                        int body_end = func["body"]["end"];
                        return std::max(overall_end, body_end);
                    }
                }
            }
        }

        return -1;
    }

    std::vector<LineRange> getConditionsForLine(llvm::Function* F, int line, const std::string& json_file_path) {
        auto* cf = getControlFlow(F, json_file_path);
        if (cf) {
            return cf->getWrappingConditions(line);
        }
        return {};
    }

    std::vector<LineRange> getConditionBodyForLine(llvm::Function* F, int line, const std::string& json_file_path) {
        auto* cf = getControlFlow(F, json_file_path);
        if (cf) {
            return cf->getWrappingBodies(line);
        }
        return {};
    }

    std::vector<int> getSwCaseBreakForLine(llvm::Function* F, int line, const std::string& json_file_path) {
        auto* cf = getControlFlow(F, json_file_path);
        if (cf) {
            return cf->getWrappingSwitchControlFlowNode(line);
        }
        return {};
    }

    std::vector<std::shared_ptr<ControlFlowNode>> getAllControlFlowNode(llvm::Function* F, const std::string& json_file_path){
        auto* cf = getControlFlow(F, json_file_path);
        if (cf)
            return cf->control_flow;
        return {};
    }

    std::vector<int> getFunctionDeclarationScope(llvm::Function* F, const std::string& json_file_path) {
        auto* cf = getControlFlow(F, json_file_path);
        if (cf == nullptr) {
            return {};
        }

        std::vector<int> result;
        result.push_back(cf->overall_start);
        result.push_back(cf->overall_end);
        for (int i = cf->overall_start; i < cf->body_start; ++i) {
            result.push_back(i);
        }
        return result;
    }

    std::vector<LabelInfo> getAllLabelNode(llvm::Function* F, const std::string& json_file_path) {
        auto* cf = getControlFlow(F, json_file_path);
        if (cf)
            return cf->labels;
        return {};
    }

    std::vector<ControlFlowNode*> getAllControlFlowNodeForLine(llvm::Function* F, int line, const std::string& json_file_path) {
        auto* cf = getControlFlow(F, json_file_path);
        if (cf) {
            return cf->getWrappingNodes(line);
        }
        return {};
    }
    
    bool checkLineInLineRange(LineRange line_range, std::set<int> lineVec) {
        int start = line_range.start;
        int end = line_range.end;
        for (int line : lineVec) {
            if (line >= start && line <= end) {
                return true;
            }
        }
        return false;
    }
    
    bool checkLineInLineRange(LineRange line_range, std::vector<std::pair<int, std::string>> lineStrVec) {
        int start = line_range.start;
        int end = line_range.end;
        for (auto line : lineStrVec) {
            if (line.first >= start && line.first <= end) {

                return true;
            }
        }
        return false;
    }
    
    bool checkLineInVector(int line, std::set<int> line_range) {
        if (line_range.find(line) != line_range.end()) {
            return true;
        }
        return false;
    }
    bool checkLineInVector(int line, std::vector<std::pair<int, std::string>> lineStrVec) {
        for (auto entry : lineStrVec) {
            if (entry.first == line) {
                return true;
            }
        }
        return false;
    }
    
    std::vector<int> checkMissingLines(int start, int end, std::vector<std::pair<int, std::string>> line_range) {
        std::vector<int> missing_lines;
        for (auto entry: line_range) {
            if (entry.first > start && entry.first < end) {
                missing_lines.push_back(entry.first);
            }
        }
        return missing_lines;
    }

    std::vector<int> getNonFunctionBody(llvm::Function* F, const std::string& json_file_path) {
        auto* cf = getControlFlow(F, json_file_path);
        int overall_start = cf->overall_start;
        int body_start = cf->body_start;
        int overall_end = cf->overall_end;

        std::vector<int> result;
        for (int i = overall_start; i <= body_start; ++i) {
            result.push_back(i);
        }
        result.push_back(overall_end);

        return result;
    }

    bool checkLineInLabelRange(llvm::Function* F, int line, const std::string& json_file_path) {
        auto* cf = getControlFlow(F, json_file_path);
        if (cf) {
            for (const auto& label : cf->labels) {
                if (line >= label.range.start && line <= label.range.end) {
                    return true;
                }
            }
        }
        return false;
    }

    std::vector<int> getLabelRangeForLine(llvm::Function* F, int line, const std::string& json_file_path) {
        auto* cf = getControlFlow(F, json_file_path);
        std::vector<int> results;

        if (cf) {
            for (const auto& label : cf->labels) {
                if (line >= label.range.start && line <= label.range.end) {
                    for (int i = label.range.start; i <= label.range.end; ++i) {
                        results.push_back(i);
                    }
                    return results;
                }
            }
        }
        return results;
    }

    int getLabelLineForLine(llvm::Function* F, int line, const std::string& json_file_path) {
        auto* cf = getControlFlow(F, json_file_path);

        if (cf) {
            for (const auto& label : cf->labels) {
                if (line >= label.range.start && line <= label.range.end) {
                    for (int i = label.range.start; i <= label.range.end; ++i) {
                        return label.range.start;
                    }
                }
            }
        }
        return -1;
    }


private:
    ControlFlowManager() = default;

    FunctionControlFlow* getControlFlow(llvm::Function* F, const std::string& json_file_path) {
        auto it = function_map.find(F);
        if (it != function_map.end()) {
            return &it->second;
        }

        if (F->getName().equals("process_receive.42")) {
            errs() << "process_receive.42\n";
        }

        // 缓存中没有，加载 JSON 文件
        loadJsonFile(F, json_file_path);
        it = function_map.find(F);
        if (it != function_map.end()) {
            return &it->second;
        }
        llvm::errs() << "Warning: No control flow info found for function " << F->getName() << "\n";
        return nullptr;
    }

    std::unordered_map<llvm::Function*, FunctionControlFlow> function_map;

    void loadJsonFile(llvm::Function* F, const std::string& json_file_path) {
        std::ifstream ifs(json_file_path);
        if (!ifs.is_open()) {
            llvm::errs() << "Error: Cannot open JSON file: " << json_file_path << "\n";
            return;
        }
        json j;
        ifs >> j;
        ifs.close();

        std::string source_file = j["source_file"].get<std::string>();
        std::string target_func_name = F->getName().str();

        for (const auto& func_json : j["functions"]) {
            FunctionControlFlow func;
            func.name = func_json["name"].get<std::string>();

            if (target_func_name.find('.') != std::string::npos && 
                target_func_name.find(func.name.substr(0, target_func_name.find('.'))) == 0) {
                func.name = target_func_name;
            }

            func.source_file = source_file;

            if (!func_json.contains("overall")) {
                continue;
            }

            func.overall_start = func_json["overall"]["start"];
            func.overall_end = func_json["overall"]["end"];
            func.body_start = func_json["body"]["start"];
            func.body_end = func_json["body"]["end"];

            for (const auto& node_json : func_json["control_flow"]) {
                auto node = parseNode(node_json);
                func.control_flow.push_back(node);
                indexNode(node.get(), func);
            }

            if (func_json.contains("labels")) {
                for (const auto& label_json : func_json["labels"]) {
                    LabelInfo label;
                    label.name = label_json["name"].get<std::string>();
                    int start = label_json["range"]["start"].get<int>();
                    int end = label_json["range"]["end"].get<int>();
                    label.range = LineRange(start, end);
                    func.labels.push_back(label);
                }
            }

            if (func.name == target_func_name) {
                function_map[F] = func;
            }
        }
    }

    std::shared_ptr<ControlFlowNode> parseNode(const json& node_json) {
        AST_NODE_TYPE type;
        std::string type_str = node_json["type"].get<std::string>();
        if (type_str == "IF") type = AST_NODE_TYPE_IF;
        else if (type_str == "WHILE") type = AST_NODE_TYPE_WHILE;
        else if (type_str == "FOR") type = AST_NODE_TYPE_FOR;
        else if (type_str == "SWITCH") type = AST_NODE_TYPE_SWITCH;
        else {
            llvm::errs() << "Warning: Unknown node type: " << type_str << "\n";
            type = AST_NODE_TYPE_UNKNOWN; // 默认值
        }

        LineRange condition(node_json["location"]["condition"]["start"], node_json["location"]["condition"]["end"]);
        LineRange body(node_json["location"]["body"]["start"], node_json["location"]["body"]["end"]);
        LineRange full(node_json["location"]["full"]["start"], node_json["location"]["full"]["end"]);

        LocationInfo loc(condition, body, full);

        if (node_json["location"].contains("else")) {
            LineRange else_(node_json["location"]["else"]["start"], node_json["location"]["else"]["end"]);
            loc = LocationInfo(condition, body, full, else_);
        }

        if (type == AST_NODE_TYPE_SWITCH) {
            if (node_json.contains("case_lines")) {
                for (const auto& line : node_json["case_lines"]) {
                    loc.caseVec.push_back(line.get<int>());
                }
            }
            
            if (node_json.contains("break_lines")) {
                for (const auto& line : node_json["break_lines"]) {
                    loc.breakVec.push_back(line.get<int>());
                }
            }

            loc.default_line = node_json.value("default_line", -1);
        }

        int depth = node_json["depth"].get<int>();
        auto node = std::make_shared<ControlFlowNode>(type, loc, depth);

        if (node_json.contains("children")) {
            for (const auto& child_json : node_json["children"]) {
                auto child = parseNode(child_json);
                node->children.push_back(child);
            }
        }
        return node;
    }

    void indexNode(ControlFlowNode* node, FunctionControlFlow& func) {
        for (int line = node->location.full.start; line <= node->location.full.end; ++line) {
            func.line_to_nodes[line].push_back(node);
        }
        for (const auto& child : node->children) {
            indexNode(child.get(), func);
        }
    }
    void indexTopLevelNode(ControlFlowNode* node, FunctionControlFlow& func) {
        for (int line = node->location.full.start; line <= node->location.full.end; ++line) {
            func.line_to_parent_nodes[line].push_back(node);
        }
    }
};


struct FunctionDebugInfo {
    std::map<int, std::string> lineToCode;           
    std::map<int, std::vector<Instruction*>> lineToInsts; 
    std::map<std::string, std::vector<Instruction*>> varToInsts; 
    bool isInitialized = false;
};

/**
 * @brief A utility struct for logging the duration of LLM (Large Language Model) queries.
 * 
 * This struct logs the time taken for an LLM query from its creation to its destruction.
 * It logs whether the query succeeded or failed, the duration in milliseconds, and the model type used.
 * 
 * @param model_type The type of the model being used for the LLM query.
 * 
 * @note The logging happens automatically when an instance of this struct goes out of scope.
 */
struct ScopedLLMTimeLogger {
    std::chrono::steady_clock::time_point start;
    std::string model;
    bool success = false;
    
    ScopedLLMTimeLogger(const std::string& model_type) : 
        start(std::chrono::steady_clock::now()),
        model(model_type) {}
    
    ~ScopedLLMTimeLogger() {
        auto end = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        if (duration.count() != 0)
            errs() << "[LLM Query] " << (success ? "Succeeded" : "Failed")
               << " in " << duration.count() << " ms. Model: " << model << ".\n";
    }
};


// Function Declarations

bool validateLLMResponse(const string response);

void importPacketRelatedFuncs(Module &M, 
                             const std::string &reportPath,
                             std::set<Function*> &packetRelatedFuncs,
                             std::map<Function*, std::set<Function*>> &packetRelatedCallGraph);
                            
size_t WriteCallback(void *contents, size_t size, size_t nmemb, string *response);

string queryLLMModel(const string &prompt, const string &model);

bool performOneLLMQuery(const std::string prompt, std::string &response, int prompt_type, const string model_type, std::string rule_desc);
bool performOneLLMQuery_multithread(std::string prompt, std::string &response, int prompt_type, std::string model_type, std::string rule_desc);

bool readRulesFromJson(const std::string &filename, std::map<std::string, std::vector<Rule>> &RulesMap);

std::string getFunctionSourceCode(llvm::Function *F);
std::string getLineFromFile(const std::string &filePath, unsigned lineNumber, bool trimFlag);
std::string getLineFromFile_perpro(Function* func, unsigned lineNumber, bool trimFlag);

int getLineForPHINodeSecondary(BasicBlock *BB, PHINode *phiNodeInst);
std::map<int, std::string> getFunctionSourceCodeMap(llvm::Function *F);
std::vector<std::pair<int, std::string>> getFunctionSourceCodeVector(llvm::Function *F);

std::string delLLVMIRInfoForVar(std::string varName);
Instruction* findInstructionByVarNameDef(Function* func, std::string varName, std::string varDef);
std::vector<Value*> findInstructionsByVarName(Function* func, std::string varName);

Instruction* findDbgDeclareInstruction(Function* func, std::string varName, int lineNum);

std::string generateGeneralMessagePrompt(const std::string &protocolName, const std::string &sourceCode);
std::string generateMessageHandlerPrompt(const std::string &protocolName, const std::string &sourceCode, const std::string &messageType);
std::string generateRequestMessageFieldPrompt(const std::string &protocolName, const std::string &sourceCode, const std::string &messageType, const std::vector<std::string> &fieldVec);
std::string generateMessageFieldPrompt(const std::string &protocolName, const std::string &sourceCode, const std::string &messageType, const std::vector<std::string> &fieldVec);
std::string generateFunctionRuleRelatedPrompt(const std::string &protocolName, int protocolVersion, const std::string &sourceCode, const Rule &rule);
std::string generateSendingFunctionRelatedPrompt(const std::string &protocolName, const std::string &sourceCode);
std::string generateBacktraceSendingFunctionRelatedPrompt(const std::string &protocolName, const std::string &sourceCode, const std::vector<std::string> &messageType);
std::string generateCompleteCodeSlicePrompt(const std::string &ruleDesc, const std::string &codeSlice, const std::string &originalCode);
std::string generateMultiProtocolPrompt(const std::string &codeSlice);

void completeCodeSliceWithControlFlow(std::map<llvm::Function*, std::vector<std::pair<int, std::string>>> &CodeSliceLineStr);
void completeCodeSliceWithMethodBoundaries(std::map<llvm::Function*, std::vector<std::pair<int, std::string>>> &CodeSliceLineStr);
void completeCodeSliceWithConCompilationInst(std::map<llvm::Function*, std::vector<std::pair<int, std::string>>> &CodeSliceLineStr);

GepObj constructGetObj(GetElementPtrInst *GEP);
void addUniqueGepObj(std::vector<GepObj> &GepObjList, const GepObj &gepObj);
void convertGepObj2TypeMap(GepObj gepObj, std::map<Type*, std::pair<int, int>> &StructTypeMap);

std::map<std::string, std::set<Function*>> loadWPAForInDirectCall(Module &M, std::string wpa_filename);

bool queryLLMCacheResult(sqlite3* db, const std::string& hash_value, int type, std::string& out_result);

void storeLLMAnalysisResult(sqlite3* db, int prompt_type,
                          const std::string& hash_value,
                          const std::string& prompt_content,
                          const std::string& result,
                          const std::string& rule_desc);

std::pair<std::string, std::string> getMostFrequentResult(const std::vector<std::pair<std::string, std::string>>& successfulResults);
void completeResponseFunction(Function* msgFuncEntry, std::map<Function*, std::set<Function*>> CallGraph, 
    std::map<Function*, std::set<Value*>> &InstSliceCode, Rule rule);

void extractGeneralRecvFunction(std::set<Function*> msgFuncEntry, Module &M, Rule rule, std::set<Function*> &resultFunctions, std::map<Function*, std::set<Function*>> packetRelatedCallGraph);

void readConfigFile(string configPath);

sqlite3* initialize_database(std::string db_path);

bool isFunctionContainedIn(Function* current,
                           Function* target,
                           std::map<Function*, std::set<Function*>>& callGraph,
                           std::unordered_set<Function*>& visited);

bool containsSystemCall(Function* startFunc,
                        const std::set<std::string>& syscallNames,
                        const std::map<Function*, std::set<Function*>>& callGraph);


std::set<Function*> findTopLevelEntries(
    const std::set<Function*>& msgFuncEntry,
    const std::map<Function*, std::set<Function*>>& callGraph);

std::map<Function*, std::pair<int, int>> readFunctionArgSummary(Module &M, const std::string &filePath);

std::unique_ptr<Module> loadModuleFromFile(std::string IRFilePath, Module &M);

std::vector<Instruction*> findInstructionsByLine(Function *F, int line);
std::vector<Instruction*> findInstructionsByLine(Function *F, std::vector<int> lines);
std::set<Value*> findInstructionsByVarStringInfo(Function* func, std::string varName, std::string struct_flag, std::string access_line, std::string definition_line,
    std::vector<GepObj> &GepObjList, 
    std::map<Type*, std::pair<int, int>> &StructTypeMap);

std::set<Instruction*> backwardSliceCondition(std::vector<Instruction*> conditionInsts);


std::vector<int> getInstructionLine(Instruction* inst, Module* M);

std::map<Function*, std::set<int>> convertCodeSliceToLineSlice(const std::map<Function*, std::set<Value*>> &codeSlice, Module*  M);
std::map<Function*, std::set<int>> addCaseDefaultBreak(std::map<Function*, std::set<int>> &codeSlice);

std::map<llvm::Function*, std::vector<std::pair<int, std::string>>> getCodeSliceLines(std::map<llvm::Function*, std::set<int>> codeSliceLines);

int getEffectiveIndent(const std::string& line);

std::vector<std::string> readEntireFile(const std::string& filename);

std::set<Instruction*> forwardSliceCondition(std::vector<Instruction*> conditionInsts, std::map<Function*, std::pair<int, int>> funcArgSummary);

std::string trimToBrace(const std::string& lineCode, int startFlag);

void completeControlFlowStatements(Function* curFunc, LineRange bodyRange, std::map<llvm::Function*, std::vector<std::pair<int, std::string>>>& completeCodeSliceLines);
std::map<llvm::Function*, std::vector<std::pair<int, std::string>>> completeCodeSliceLine(std::map<llvm::Function*, std::vector<std::pair<int, std::string>>> codeSliceLineStr);

std::map<llvm::Function*, std::vector<std::pair<int, std::string>>> mergeCodeSliceLineStrs(std::map<llvm::Function*, std::vector<std::pair<int, std::string>>> first1, std::map<llvm::Function*, std::vector<std::pair<int, std::string>>> first2);

bool isLineInCodeSlice(Function *function, int lineNumber, const std::map<llvm::Function*, std::vector<std::pair<int, std::string>>>& codeSliceLineStr);
std::vector<int> getMissingLinesInRange(
    Function *function,
    const LineRange& range, 
    const std::map<llvm::Function*, std::vector<std::pair<int, std::string>>>& codeSliceLineStr);

void processRangeBoundary(Function* func, int lineNum, const std::string& sourceFile,
    std::map<llvm::Function*, std::vector<std::pair<int, std::string>>>& CodeSliceLineStr,
    bool& addFlag, std::set<int> &newAddLine);
void processMissingLines(Function* func, const LineRange& range, const std::string& sourceFile,
        std::map<llvm::Function*, std::vector<std::pair<int, std::string>>>& CodeSliceLineStr,
        bool& addFlag);

std::map<llvm::Function*, std::vector<std::pair<int, std::string>>> 
sortCodeSliceLines(std::map<llvm::Function*, std::vector<std::pair<int, std::string>>> codeSliceLineStr);

void completeCodeSlicePro(std::map<llvm::Function*, std::vector<std::pair<int, std::string>>> &CodeSliceLineStr);
void llmCompleteCodeSlicePro(Rule rule, std::map<llvm::Function*, std::vector<std::pair<int, std::string>>> &CodeSliceLineStr);
void llmCompleteCodeSlicePro_multithread(Rule rule, std::map<llvm::Function*, std::vector<std::pair<int, std::string>>> &CodeSliceLineStr);

void sortCodeSliceLines(
    std::map<llvm::Function*, std::vector<std::pair<int, std::string>>>& codeSliceLineStr,
    llvm::Function* targetFunc);

void completeCodeSliceHelper(std::shared_ptr<ControlFlowNode> CFNode,
    ControlFlowManager CFM,
    llvm::Function* func,
    std::string sourceFile, 
    const std::vector<std::pair<int, std::string>>& lines,
    std::map<llvm::Function*, std::vector<std::pair<int, std::string>>>& completeCodeSliceLines);

void processNodeRecursive(
    const std::shared_ptr<ControlFlowNode>& node,
    ControlFlowManager& CFM,
    llvm::Function* func,
    const std::string& sourceFile,
    const std::vector<std::pair<int, std::string>>& originalLines,
    std::map<llvm::Function*, std::vector<std::pair<int, std::string>>>& result);

std::string printCallTree(
    const std::map<llvm::Function*, std::vector<std::pair<int, std::string>>>& mergedCodeSliceLineStr,
    const std::map<llvm::Function*, std::set<llvm::Function*>>& CallGraph,
    llvm::Function* entryPoint);

std::string printCallTree(
    llvm::Function* entryPoint,
    const std::map<llvm::Function*, std::set<llvm::Function*>>& CallGraph);

std::map<llvm::Function*, std::vector<std::pair<int, std::string>>> 
    deduplicateCodeSliceLines(const std::map<llvm::Function*, std::vector<std::pair<int, std::string>>>& codeSliceLineStr);

std::map<Function*, std::set<Function*>> findAncestorFunctions(
    const std::map<Function*, std::set<Function*>> &callGraph,
    const std::set<Function*> &funcList);

std::map<llvm::Function*, std::set<llvm::Function*>> extractRuleRelatedFunctions(std::map<llvm::Function*, std::set<llvm::Function*>> callGraph, std::set<llvm::Function*> &funcList, Rule rule);
std::map<llvm::Function*, std::set<llvm::Function*>> extractRuleRelatedFunctions_multithread(std::map<llvm::Function*, std::set<llvm::Function*>> callGraph, std::set<llvm::Function*> &funcList, Rule rule);
bool checkRuleDescExists(sqlite3* db, const std::string& rule_desc);

void buildGlobalCallGraph(Module &M,
    std::map<Function*, std::set<Function*>> &CallGraphEdges,
    std::map<Function*, std::set<Function*>> &Func2CallFuncs,
    std::map<Function*, std::set<Instruction*>> &FuncInsEdges);

void storeRuleCodeSnippetResult(sqlite3* db, const std::string& rule_desc, const std::string& code_snippet, const std::string& call_graph);
std::string printCodeSnippet(std::map<llvm::Function*, std::vector<std::pair<int, std::string>>> mergedCodeSliceLineStr);

bool hasResponseMessageType(const std::map<std::string, std::vector<Rule>>& RulesMap);

std::string toLowercase(const std::string &str);

std::string extractJsonFromMarkdown(const std::string& input);


bool isFunctionReachable(Function *startFunc, Function *targetFunc, std::map<Function*, std::set<Function*>> reverseCallGraph);

std::pair<bool, Function*> checkFunctionReachability(Function* funcA, Function* funcB, std::map<Function*, std::set<Function*>>& reverseCallGraph);

std::map<Function*, std::set<Function*>> pruneCallGraphByResponse(
    std::map<Function*, std::set<Function*>> callgraph, 
    std::set<Function*> &callgraphSet,
    std::set<Function*> resSendFuncSet);

std::map<llvm::Function*, std::set<int>> converFunCodeToLine(std::set<Function*> ruleRelatedFunctionSet);

void addReponseFunction(Function *curFunction, std::string ResFunction, std::map<Function*, std::set<Value*>> &InstSliceCode);

// bool isGepObjContained(std::vector<GepObj> GepObjList, GepObj GEP);
// bool isGepObjMatched(std::vector<GepObj> GepObjList, GepObj GEP);

bool isGepObjMatched(const std::vector<GepObj>& GepObjList, const GepObj& GEP);
bool isGepObjContained(const std::vector<GepObj>& GepObjList, const GepObj& GEP);

void refineProcessSubFunctionInst(Instruction *inst, std::map<Function*, std::set<Value*>> &InstSliceCode);

std::string extractBaseVariableName(const std::string& variableExpression);

size_t getInstSliceCodeSize(const std::map<Function*, std::set<Value*>> &InstSliceCode);

std::string vectorToString(const std::vector<std::string> &vec);

std::string promptToString(int prompt);

bool is_case_statement(const std::string& line);
bool is_break_statement(const std::string& line);
bool is_continue_statement(const std::string& line);
std::string convertVectorToString(const std::vector<std::pair<int, std::string>>& vec);

const FunctionDebugInfo& getOrCreateFunctionDebugInfo(Function* func);
std::vector<Value*> findInstructionsByVarName_perpro(Function* func, std::string varName);
const FunctionDebugInfo& getOrCreateFunctionLineCode(Function* func);