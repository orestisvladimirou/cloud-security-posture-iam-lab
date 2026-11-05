"""Rebuild source checksum manifest after intentional reviewed changes."""
import json
from pathlib import Path
from scripts_validate_integrity import ROOT,files_inventory

if __name__=='__main__':
    contents={'version':'0.4','purpose':'Entirely synthetic offline cloud-security portfolio exercise',
              'files':files_inventory()}
    (ROOT/'SOURCE_MANIFEST.json').write_text(json.dumps(contents,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    print(f'Manifest regenerated for {len(contents["files"])} source files')
