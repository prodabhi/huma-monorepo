#!/usr/bin/env python3
"""Fast ACIR source attribution, without rebuilding a circuit per opcode."""
import argparse,base64,collections,hashlib,json,zlib
from pathlib import Path

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('artifact',type=Path);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    program=json.loads(a.artifact.read_text())
    debug=json.loads(zlib.decompress(base64.b64decode(program['debug_symbols']),-15))['debug_infos'][0]
    files=program['file_map'];tree=debug['location_tree']['locations']
    main_files={int(k) for k,v in files.items() if str(v.get('path','')).endswith('/main.nr')}
    counts=collections.Counter(debug['acir_locations'].values());by_line=collections.Counter()
    for index,count in counts.items():
        node=tree[index]
        while node['value']['file'] not in main_files and node['parent'] is not None:node=tree[node['parent']]
        if node['value']['file'] not in main_files:continue
        file=files[str(node['value']['file'])];source=file['source'];line=source.count('\n',0,node['value']['span']['start'])+1
        by_line[(file['path'],line,source.splitlines()[line-1].strip())]+=count
    result={'bytecodeSha256':hashlib.sha256(program['bytecode'].encode()).hexdigest(),
        'countsAreAcirOpcodesNotBackendGates':True,
        'lines':[dict(path=path,line=line,source=source,acirOpcodes=count) for (path,line,source),count in by_line.most_common()]}
    a.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'sourceLines':len(by_line),'attributedOpcodes':sum(by_line.values())}))
if __name__=='__main__':main()
