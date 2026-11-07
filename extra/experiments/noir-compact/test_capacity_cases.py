import hashlib
import re
import unittest
import capacity_cases as cases

class CapacitySourceTests(unittest.TestCase):
    def test_default_matches_the_shipped_cp32_source(self):
        source=cases.circuit(dict(cases.BUCKETS['standard'],CPS=32))
        self.assertEqual(hashlib.sha256(source.encode()).hexdigest(),
            'f2d9b612782a4fc67b0941030689d96b95283b0cc6574582da88e6c1ebcab75f')

    def test_small_buckets_change_only_fixed_array_capacities(self):
        standard=cases.circuit(dict(cases.BUCKETS['standard'],CPS=32))
        globals_pattern=r'global (OPS|SCALARS|BYTES|SAMPLES|CPS|PRES):u32=\d+;'
        for name in ['short64','short128']:
            limits=cases.BUCKETS[name];source=cases.circuit(limits)
            self.assertEqual(re.sub(globals_pattern,'',source),re.sub(globals_pattern,'',standard))
            self.assertEqual({k:int(v) for k,v in re.findall(r'global (\w+):u32=(\d+);',source)},limits)
            self.assertEqual(limits['CPS'],8 if name=='short64' else 32);self.assertEqual(limits['PRES'],8)

if __name__=='__main__':unittest.main()
