"""Pinned AFLNet build with LLVM 14 support and SelectFuzz-style coverage filtering."""
from pathlib import Path
import os
import subprocess
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
COMMIT = '96032f86d0005dfeeb41ea7b31103f1d1ff8f168'
vendor = ROOT / 'output/vendor'
vendor.mkdir(parents=True, exist_ok=True)
archive = vendor / 'aflnet.tar.gz'
if not archive.exists():
    urllib.request.urlretrieve(f'https://codeload.github.com/aflnet/aflnet/tar.gz/{COMMIT}', archive)
with tarfile.open(archive) as src:
    for member in src:
        target = (vendor / member.name).resolve()
        if not target.is_relative_to(vendor.resolve()) or member.issym() or member.islnk():
            raise ValueError('Unsafe upstream archive member')
    src.extractall(vendor)
afl = vendor / ('aflnet-' + COMMIT)
path = afl / 'llvm_mode/afl-llvm-pass.so.cc'
code = path.read_text()
code = code.replace('#include "llvm/IR/Module.h"', '''#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include <fstream>
#include <set>
#include <string>''')
code = code.replace('IRB.CreateLoad(AFLPrevLoc)', 'IRB.CreateLoad(Int32Ty, AFLPrevLoc)')
code = code.replace('IRB.CreateLoad(AFLMapPtr)', 'IRB.CreateLoad(PointerType::get(Int8Ty, 0), AFLMapPtr)')
code = code.replace('IRB.CreateLoad(MapPtrIdx)', 'IRB.CreateLoad(Int8Ty, MapPtrIdx)')
code = code.replace('IRB.CreateGEP(MapPtr,', 'IRB.CreateGEP(Int8Ty, MapPtr,')
code = code.replace('  int inst_blocks = 0;', '''
  // ProtocolGuard reconstruction of SelectFuzz's selective coverage policy:
  // ctrl-data.dot is the keep set emitted by the supplied DFUZZ pass.
  std::set<std::string> pg_keep;
  const char *pg_file = getenv("PROTOCOLGUARD_KEEP_BB");
  if (pg_file) {
    std::ifstream input(pg_file); std::string line;
    if (!input) FATAL("Cannot read PROTOCOLGUARD_KEEP_BB");
    while (std::getline(input, line)) if (!line.empty()) pg_keep.insert(line);
    if (pg_keep.empty()) FATAL("Selective instrumentation keep set is empty");
  }
  int inst_blocks = 0;''')
code = code.replace('      BasicBlock::iterator IP = BB.getFirstInsertionPt();', '''
      if (pg_file) {
        std::string location;
        for (auto &I : BB) if (auto DL = I.getDebugLoc()) {
          std::string filename = DL->getFilename().str();
          if (filename.empty() || filename.rfind("/usr/", 0) == 0) continue;
          auto slash = filename.find_last_of("/\\\\");
          if (slash != std::string::npos) filename = filename.substr(slash + 1);
          location = filename + ":" + std::to_string(DL.getLine());
          break;
        }
        if (!location.empty() && !pg_keep.count(location)) continue;
      }
      BasicBlock::iterator IP = BB.getFirstInsertionPt();''')
path.write_text(code)
wrapper = afl / 'llvm_mode/afl-clang-fast.c'
code = wrapper.read_text().replace('  cc_params[cc_par_cnt++] = "-Qunused-arguments";',
    '  cc_params[cc_par_cnt++] = "-flegacy-pass-manager";\n  cc_params[cc_par_cnt++] = "-Qunused-arguments";')
wrapper.write_text(code)
env = dict(os.environ, CC='clang-14', CXX='clang++-14', LLVM_CONFIG='llvm-config-14', AFL_NO_X86='1', CFLAGS='-O2 -g -fcommon')
subprocess.run(['make', '-j2', 'afl-fuzz', 'afl-showmap', 'aflnet-replay'], cwd=afl, env=env, check=True)
subprocess.run(['make', '-j2', '../afl-clang-fast', '../afl-llvm-pass.so', '../afl-llvm-rt.o'], cwd=afl/'llvm_mode', env=env, check=True)
(vendor / 'aflnet-path.txt').write_text(str(afl))
print('Built AFLNet', COMMIT, 'with selective instrumentation')
