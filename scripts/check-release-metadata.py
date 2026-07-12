#!/usr/bin/env python3
from pathlib import Path
import sys, tomllib
errors=[]
root=tomllib.loads(Path('Cargo.toml').read_text())
wp=root.get('workspace',{}).get('package',{})
for field in ('authors','repository','license','edition','rust-version','version'):
    value=wp.get(field)
    if value is None or (isinstance(value,str) and ('TODO' in value or not value.strip())) or (isinstance(value,list) and any('TODO' in x for x in value)):
        errors.append(f'workspace.package.{field} is missing or unresolved')
for crate in ('pqc-core','pqc-ml-kem','pqc-hpke'):
    p=Path('crates')/crate/'Cargo.toml'; data=tomllib.loads(p.read_text()); pkg=data.get('package',{})
    if pkg.get('publish') is False: errors.append(f'{p}: publish=false for release crate')
for crate in ('pqc-test-harness','pqc-ml-dsa','pqc-slh-dsa'):
    p=Path('crates')/crate/'Cargo.toml'
    if p.exists() and tomllib.loads(p.read_text()).get('package',{}).get('publish') is not False:
        errors.append(f'{p}: expected publish=false')
if errors:
    print('Release metadata check failed:'); [print('-',e) for e in errors]; sys.exit(1)
print('Release metadata check passed.')
