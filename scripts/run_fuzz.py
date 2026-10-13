"""Run a bounded AFLNet smoke experiment from verified ProtocolGuard seeds.

This is deliberately a separate, short run.  The paper's 24-hour campaign is
not silently represented as complete when a local run has only exercised the
pipeline for a few seconds.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from protocolguard.common import load_config, verification_path


def run(config, seconds):
    if os.name == 'nt':
        raise RuntimeError('AFLNet smoke runs require the Linux Docker container; run scripts/run.ps1 fuzz')
    vendor_file = ROOT / 'output/vendor/aflnet-path.txt'
    if not vendor_file.is_file():
        raise RuntimeError('AFLNet is not built; run python3 scripts/setup_aflnet.py first')
    afl_root = Path(vendor_file.read_text().strip())
    afl = afl_root / 'afl-fuzz'
    if not afl.is_file():
        raise RuntimeError(f'AFLNet binary missing: {afl}')
    if config['project']['project_name'] == 'Mosquitto':
        binary = ROOT / 'output/mosquitto-build/src/mosquitto'
        protocol = 'MQTT'
        transport = 'tcp'
    else:
        binary = ROOT / 'output/sol-build/sol'
        protocol = 'MQTT'
        transport = 'tcp'
    if not binary.is_file():
        raise RuntimeError('Baseline Sol binary missing; run the build stage first')
    latest = verification_path(config) / 'latest.json'
    if not latest.is_file():
        raise RuntimeError('No dynamic-verification run found; fuzzing requires verified evidence')
    run_id = json.loads(latest.read_text())['run']
    run_dir = verification_path(config) / run_id
    verified = [p for p in run_dir.glob('rule_*/result.json')
                if json.loads(p.read_text()).get('dynamically_verified')]
    if not verified:
        raise RuntimeError(f'Verification run {run_id} has no dynamically verified rule')
    seeds = sorted(run_dir.glob('rule_*/**/*.raw'))
    if not seeds:
        raise RuntimeError(f'No raw seeds found in verified run {run_dir}')
    seed_dir = ROOT / 'output/fuzz-seeds'
    seed_dir.mkdir(parents=True, exist_ok=True)
    for old in seed_dir.iterdir():
        if old.is_file():
            old.unlink()
    for index, seed in enumerate(seeds, 1):
        shutil.copyfile(seed, seed_dir / f'{index:04d}-{seed.name}')
    output = ROOT / ('output/fuzz-mosquitto' if config['project']['project_name'] == 'Mosquitto'
                     else 'output/fuzz')
    output.mkdir(parents=True, exist_ok=True)
    if config['project']['project_name'] == 'Mosquitto':
        config_path = output / 'mosquitto.conf'
        config_path.write_text('listener 18883 127.0.0.1\nallow_anonymous true\n'
                               'persistence false\nlog_type all\nlog_dest stderr\n')
    else:
        config_path = output / 'sol.conf'
        config_path.write_text('ip_address 127.0.0.1\nip_port 18883\nlog_level INFO\n'
                               f'log_path {output / "sol.server.log"}\n')
    # The checked-in Sol binary is a baseline build.  Use AFL's dumb mode for
    # a bounded protocol-execution smoke test; directed coverage requires the
    # separate selective-instrumentation rebuild described in README.md.
    command = [str(afl), '-d', '-n', '-i', str(seed_dir), '-o', str(output), '-m', 'none',
               '-P', protocol, '-N', f'{transport}://127.0.0.1/18883', '-D', '1000', '-q', '3',
               '-s', '3', '-W', '1000', '-w', '100', '-E', '-K', '--', str(binary), '-c', str(config_path)]
    started = time.time()
    fuzz_env = dict(os.environ, AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES='1',
                    AFL_SKIP_BIN_CHECK='1', AFL_SKIP_CPUFREQ='1')
    result = subprocess.run(['timeout', '--signal=KILL', '--kill-after=2', f'{seconds}s', *command], cwd=ROOT,
                            env=fuzz_env, capture_output=True, text=True)
    report = {'duration_requested_seconds': seconds,
              'elapsed_seconds': round(time.time() - started, 3),
              'command': command, 'seed_count': len(seeds),
              'instrumentation_mode': 'dumb-smoke (baseline binary)',
              'returncode': result.returncode,
              'stdout_tail': result.stdout[-4000:], 'stderr_tail': result.stderr[-4000:]}
    (output / 'smoke-result.json').write_text(json.dumps(report, indent=2))
    if result.returncode not in (0, 124, 137, -9):
        raise RuntimeError('AFLNet smoke run failed; see output/fuzz/smoke-result.json')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', required=True)
    parser.add_argument('--seconds', type=int, default=int(os.getenv('PROTOCOLGUARD_FUZZ_SECONDS', '30')))
    args = parser.parse_args()
    if args.seconds < 1 or args.seconds > 86400:
        raise SystemExit('--seconds must be between 1 and 86400')
    run(load_config(args.config), args.seconds)
