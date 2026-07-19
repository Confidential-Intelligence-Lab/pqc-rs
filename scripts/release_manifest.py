#!/usr/bin/env python3
import subprocess,sys
raise SystemExit(subprocess.call([sys.executable,"scripts/release_artifacts.py","manifest",*sys.argv[1:]]))
