#!/usr/bin/env python3
"""Generate /usr/bin wrappers for console_scripts declared in dist-info."""
import configparser, os, sys

site_pkgs, usr_bin = sys.argv[1], sys.argv[2]
os.makedirs(usr_bin, exist_ok=True)

for d in sorted(os.listdir(site_pkgs)):
    if not d.endswith('.dist-info'):
        continue
    ep_file = os.path.join(site_pkgs, d, 'entry_points.txt')
    if not os.path.exists(ep_file):
        continue
    cfg = configparser.ConfigParser()
    cfg.read(ep_file)
    if 'console_scripts' not in cfg:
        continue
    for name, target in cfg['console_scripts'].items():
        name = name.strip()
        module, func = [s.strip() for s in target.strip().split(':')]
        path = os.path.join(usr_bin, name)
        with open(path, 'w') as f:
            f.write('#!/usr/bin/python3\n')
            f.write('import sys\n')
            f.write(f'from {module} import {func}\n')
            f.write(f'sys.exit({func}())\n')
        os.chmod(path, 0o755)
        print(f'  → {path}')
