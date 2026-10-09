#!/usr/bin/env python3
"""Prepare hash-pinned Git sources and recipe inputs; never compile on the host."""
import hashlib
import io
import json
import pathlib
import re
import subprocess
import sys
import tarfile


def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def main():
    recipe, destination, cache = map(pathlib.Path, sys.argv[1:])
    lock = json.loads((recipe / 'kms-sources.lock.json').read_text())
    destination.mkdir(parents=True, exist_ok=True)
    cache.mkdir(parents=True, exist_ok=True)
    inputs = (
        'KmsBuilder.Dockerfile', 'ubuntu-snapshot.sources', 'ubuntu-snapshot-ca.pem',
        'kms-build-apt.lock', 'kms-sources.lock.json', 'kms-nsm-Cargo.lock',
        'kms-compile.sh', 'kms_prepare.py', 'build-kms-helper.sh',
    )
    hashes = {}
    for name in inputs:
        source = recipe / name
        contents = source.read_bytes()
        hashes['nitro/' + name] = hashlib.sha256(contents).hexdigest()
        (destination / name).write_bytes(contents)
    with tarfile.open(destination / 'sources.tar', 'w', format=tarfile.PAX_FORMAT) as combined:
        for source in lock['sources']:
            name, commit, url = source['name'], source['commit'], source['url']
            if not re.fullmatch(r'[a-z0-9-]+', name) or not re.fullmatch(r'[0-9a-f]{40}', commit):
                raise ValueError('invalid pinned Git source')
            if not url.startswith('https://github.com/') or not url.endswith('.git'):
                raise ValueError('non-HTTPS GitHub source')
            repository = cache / name
            if not repository.exists():
                run('git', 'init', '--bare', str(repository))
            exists = subprocess.run(('git', '-C', str(repository), 'cat-file', '-e', commit + '^{commit}'),
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
            if not exists:
                run('git', '-C', str(repository), 'fetch', '--depth=1', '--no-tags', url, commit)
            run('git', '-C', str(repository), 'fsck', '--full', '--no-reflogs')
            actual = subprocess.check_output(('git', '-C', str(repository), 'rev-parse', commit + '^{commit}'), text=True).strip()
            if actual != commit:
                raise ValueError('Git commit does not match source lock')
            archive = subprocess.check_output(('git', '-c', 'tar.umask=0000',
                                               '-c', 'core.attributesFile=/dev/null',
                                               '-C', str(repository), 'archive', '--format=tar',
                                               '--prefix=' + name + '/', commit))
            with tarfile.open(fileobj=io.BytesIO(archive)) as upstream:
                for member in upstream:
                    path = pathlib.PurePosixPath(member.name)
                    if path.is_absolute() or '..' in path.parts:
                        raise ValueError('unsafe source archive path')
                    member.uid = member.gid = 0
                    member.uname = member.gname = ''
                    member.mtime = lock['source_date_epoch']
                    member.pax_headers = {}
                    if member.isdir():
                        member.mode = 0o755
                    elif member.issym():
                        member.mode = 0o777
                    elif member.isfile():
                        member.mode = 0o755 if member.mode & 0o111 else 0o644
                    else:
                        raise ValueError('unexpected source archive entry type')
                    combined.addfile(member, upstream.extractfile(member) if member.isfile() else None)
    (destination / 'context-sha256.json').write_text(json.dumps(hashes, indent=2, sort_keys=True) + '\n')
    prepared = {'sources.tar': hashlib.sha256((destination / 'sources.tar').read_bytes()).hexdigest()}
    (destination / 'prepared-source-sha256.json').write_text(json.dumps(prepared, indent=2, sort_keys=True) + '\n')


if __name__ == '__main__':
    main()
