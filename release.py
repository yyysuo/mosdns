# !/usr/bin/env python3
import argparse
import logging
import os
import subprocess
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed

parser = argparse.ArgumentParser()
parser.add_argument("-i", type=int)
args = parser.parse_args()

PROJECT_NAME = 'mosdns'
RELEASE_DIR = './release'

logger = logging.getLogger(__name__)

# more info: https://golang.org/doc/install/source
# [(env : value),(env : value)]
envs = [
    [['GOOS', 'android'], ['GOARCH', 'arm64']],
    [['GOOS', 'darwin'], ['GOARCH', 'amd64']],
    [['GOOS', 'darwin'], ['GOARCH', 'arm64']],
    [['GOOS', 'windows'], ['GOARCH', 'amd64']],
    [['GOOS', 'windows'], ['GOARCH', 'amd64'], ['GOAMD64', 'v3']],
    [['GOOS', 'windows'], ['GOARCH', 'arm64']],
    [['GOOS', 'linux'], ['GOARCH', 'amd64']],
    [['GOOS', 'linux'], ['GOARCH', 'amd64'], ['GOAMD64', 'v3']],
    [['GOOS', 'linux'], ['GOARCH', 'arm64']],
    [['GOOS', 'linux'], ['GOARCH', 'arm'], ['GOARM', '5']],
    [['GOOS', 'linux'], ['GOARCH', 'arm'], ['GOARM', '6']],
    [['GOOS', 'linux'], ['GOARCH', 'arm'], ['GOARM', '7']],
    [['GOOS', 'linux'], ['GOARCH', 'mips']],
    [['GOOS', 'linux'], ['GOARCH', 'mips'], ['GOMIPS', 'softfloat']],
    [['GOOS', 'linux'], ['GOARCH', 'mips64']],
    [['GOOS', 'linux'], ['GOARCH', 'mips64'], ['GOMIPS64', 'softfloat']],
    [['GOOS', 'linux'], ['GOARCH', 'mipsle']],
    [['GOOS', 'linux'], ['GOARCH', 'mipsle'], ['GOMIPS', 'softfloat']],
    [['GOOS', 'linux'], ['GOARCH', 'mips64le']],
    [['GOOS', 'linux'], ['GOARCH', 'mips64le'], ['GOMIPS64', 'softfloat']]
]


def go_build():
    logger.info(f'building {PROJECT_NAME}')

    global envs
    if args.i:
        envs = [envs[args.i]]

    VERSION = 'dev/unknown'
    try:
        VERSION = subprocess.check_output('git describe --tags --long --always', shell=True).decode().rstrip()
    except subprocess.CalledProcessError as e:
        logger.error(f'get git tag failed: {e.args}')

    try:
        subprocess.check_call('go run ../ config gen config.yaml', shell=True, env=os.environ)
    except Exception:
        logger.exception('failed to generate config template')
        raise

    def build_one(target_env, version):
        os_env = os.environ.copy()

        s = PROJECT_NAME
        for pairs in target_env:
            os_env[pairs[0]] = pairs[1]
            s = s + '-' + pairs[1]

        zip_filename = s + '.zip'
        suffix = '.exe' if os_env['GOOS'] == 'windows' else ''
        bin_filename = PROJECT_NAME + suffix

        # Avoid filename collisions when building in parallel
        build_dir = os.path.join('build', s)
        os.makedirs(build_dir, exist_ok=True)
        bin_path = os.path.join(build_dir, bin_filename)

        logger.info(f'building {zip_filename}')
        try:
            subprocess.check_call(
                f'go build -ldflags "-s -w -X main.version={version}" -trimpath -o {bin_path} ../',
                shell=True,
                env=os_env)

            with zipfile.ZipFile(zip_filename, mode='w', compression=zipfile.ZIP_DEFLATED, compresslevel=5) as zf:
                # keep binary name inside archive as original `mosdns[.exe]`
                zf.write(bin_path, arcname=bin_filename)
                zf.write('../README.md', 'README.md')
                zf.write('./config.yaml', 'config.yaml')
                zf.write('../LICENSE', 'LICENSE')

            return True, s
        except subprocess.CalledProcessError as e:
            logger.error(f'build {zip_filename} failed: {e.args}')
            return False, s
        except Exception:
            logger.exception('unknown err')
            return False, s

    max_workers = int(os.getenv('MAX_WORKERS', os.cpu_count() or 2))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(build_one, env, VERSION) for env in envs]
        for fut in as_completed(futures):
            # Drain exceptions to avoid silent thread termination
            try:
                fut.result()
            except Exception:
                logger.exception('worker crashed')


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)

    if len(RELEASE_DIR) != 0:
        if not os.path.exists(RELEASE_DIR):
            os.mkdir(RELEASE_DIR)
        os.chdir(RELEASE_DIR)

    go_build()
