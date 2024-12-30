import argparse

from keri.core.coring import MtrDex, Matter
from keri.core.indexing import IdrDex, Indexer
from keri.core.counting import CtrDex_1_0, Counter
from json import dumps

keys = []
for key in dir(MtrDex):
    if not key.startswith('__'):
        code = getattr(MtrDex, key)
        sizes = Matter.Sizes.get(code)
        keys.append({
            "name": key,
            "code": code,
            "type": "matter",
            "hs": sizes.hs if sizes else None,
            "fs": sizes.fs if sizes else None,
            "ss": sizes.ss if sizes else None,
            "ls": sizes.ls if sizes else None,
            "xs": sizes.xs if sizes else None,
        })

for key in dir(IdrDex):
    if not key.startswith('__'):
        code = getattr(IdrDex, key)
        sizes = Indexer.Sizes.get(code)
        keys.append({
            "name": key,
            "code": code,
            "type": "indexer",
            "hs": sizes.hs if sizes else None,
            "fs": sizes.fs if sizes else None,
            "ss": sizes.ss if sizes else None,
            "ls": sizes.ls if sizes else None,
            "xs": None,
        })

for key in dir(CtrDex_1_0):
    if not key.startswith('__'):
        code = getattr(CtrDex_1_0, key)
        sizes = Counter.Sizes.get(1).get(0).get(code)
        keys.append({
            "name": key,
            "code": code,
            "type": "counter",
            "hs": sizes.hs if sizes else None,
            "fs": sizes.fs if sizes else None,
            "ss": sizes.ss if sizes else None,
            "ls": None,
            "xs": None,
        })


print(dumps(keys, indent=2))

