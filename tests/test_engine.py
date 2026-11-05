import copy
import json
import unittest
from pathlib import Path
from cloudguard.engine import InvalidSnapshot, compare, load_snapshot, scan, summarize, validate

ROOT=Path(__file__).resolve().parents[1]


class ScannerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vulnerable=load_snapshot(ROOT/'fixtures/vulnerable.json')
        cls.hardened=load_snapshot(ROOT/'fixtures/hardened.json')

    def clean(self):
        return copy.deepcopy(self.hardened)

    def rules(self, snap):
        return {f.rule_id for f in scan(snap)}

    def test_all_15_planted_findings(self):
        f=scan(self.vulnerable)
        self.assertEqual(len(f),15)
        self.assertEqual(summarize(f),{'Critical':8,'High':5,'Medium':2,'Low':0})
        self.assertEqual(len({x.finding_id for x in f}),15)

    def test_remediated_fixture_is_clean_under_defined_rules(self):
        self.assertEqual(scan(self.hardened),[])

    def test_comparison_is_not_compliance_certification(self):
        delta=compare(scan(self.vulnerable),scan(self.hardened))
        self.assertEqual(len(delta['resolved']),15)
        self.assertEqual(delta['introduced'],[])
        self.assertEqual(delta['persistent'],[])

    def test_deterministic_order(self):
        a=scan(self.vulnerable)
        self.assertEqual(a,scan(self.vulnerable))
        self.assertEqual(a[0].severity,'Critical')

    def test_root_mfa_detection(self):
        s=self.clean();s['accounts'][0]['root']['mfa_enabled']=False
        self.assertIn('IAM-001',self.rules(s))

    def test_root_access_key_detection(self):
        s=self.clean();s['accounts'][0]['root']['access_keys_active']=True
        self.assertIn('IAM-002',self.rules(s))

    def test_wildcard_role_trust(self):
        s=self.clean();s['accounts'][0]['roles'][0]['trust_principals']=['*']
        self.assertIn('IAM-003',self.rules(s))

    def test_full_admin_policy(self):
        s=self.clean();s['accounts'][0]['roles'][0]['policies']=[{'Effect':'Allow','Action':'*','Resource':'*'}]
        self.assertIn('IAM-004',self.rules(s))

    def test_denied_admin_not_a_positive(self):
        s=self.clean();s['accounts'][0]['roles'][0]['policies']=[{'Effect':'Deny','Action':'*','Resource':'*'}]
        self.assertNotIn('IAM-004',self.rules(s))

    def test_service_wildcard(self):
        s=self.clean();s['accounts'][0]['roles'][0]['policies']=[{'Effect':'Allow','Action':['s3:*'],'Resource':['*']}]
        self.assertIn('IAM-005',self.rules(s))
        self.assertNotIn('IAM-004',self.rules(s))

    def test_resource_scoped_service_wildcard_not_flagged(self):
        s=self.clean();s['accounts'][0]['roles'][0]['policies']=[{'Effect':'Allow','Action':'s3:*','Resource':'arn:aws:s3:::lab-build-artifacts/*'}]
        self.assertNotIn('IAM-005',self.rules(s))

    def test_bpa_missing_one_flag(self):
        s=self.clean();s['accounts'][0]['buckets'][0]['block_public_access']['IgnorePublicAcls']=False
        self.assertIn('S3-001',self.rules(s))

    def test_public_bucket_policy_severity_depends_on_bpa(self):
        s=self.clean();s['accounts'][0]['buckets'][0]['policy']=[{'Effect':'Allow','Principal':'*','Action':'s3:GetObject'}]
        found=[x for x in scan(s) if x.rule_id=='S3-002']
        self.assertEqual(found[0].severity,'Medium')
        s['accounts'][0]['buckets'][0]['block_public_access']['BlockPublicPolicy']=False
        found=[x for x in scan(s) if x.rule_id=='S3-002']
        self.assertEqual(found[0].severity,'Critical')

    def test_bucket_encryption(self):
        s=self.clean();s['accounts'][0]['buckets'][0]['encryption']='none'
        self.assertIn('S3-003',self.rules(s))

    def test_bucket_versioning(self):
        s=self.clean();s['accounts'][0]['buckets'][0]['versioning']=False
        self.assertIn('S3-004',self.rules(s))

    def test_world_open_ssh_ipv6(self):
        s=self.clean();s['accounts'][0]['security_groups'][0]['inbound'].append({'protocol':'tcp','from_port':22,'to_port':22,'cidr':'::/0'})
        self.assertIn('NET-001',self.rules(s))

    def test_private_ssh_not_flagged(self):
        s=self.clean();s['accounts'][0]['security_groups'][0]['inbound'].append({'protocol':'tcp','from_port':22,'to_port':22,'cidr':'10.0.0.0/8'})
        self.assertNotIn('NET-001',self.rules(s))

    def test_public_https_not_flagged(self):
        self.assertNotIn('NET-001',self.rules(self.clean()))
        self.assertNotIn('NET-002',self.rules(self.clean()))

    def test_world_open_database(self):
        s=self.clean();s['accounts'][0]['security_groups'][0]['inbound'].append({'protocol':'tcp','from_port':5432,'to_port':5432,'cidr':'0.0.0.0/0'})
        self.assertIn('NET-002',self.rules(s))

    def test_cloudtrail_disabled(self):
        s=self.clean();s['accounts'][0]['logging']['cloudtrail_enabled']=False
        self.assertIn('MON-001',self.rules(s))

    def test_cloudtrail_single_region(self):
        s=self.clean();s['accounts'][0]['logging']['cloudtrail_multi_region']=False
        self.assertIn('MON-002',self.rules(s))

    def test_log_validation_disabled(self):
        s=self.clean();s['accounts'][0]['logging']['cloudtrail_log_validation']=False
        self.assertIn('MON-003',self.rules(s))

    def test_config_disabled(self):
        s=self.clean();s['accounts'][0]['logging']['config_recorder_enabled']=False
        self.assertIn('MON-004',self.rules(s))


class SchemaValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.valid=load_snapshot(ROOT/'fixtures/hardened.json')

    def test_refuses_non_synthetic(self):
        s=copy.deepcopy(self.valid);s['synthetic']=False
        with self.assertRaises(InvalidSnapshot):validate(s)

    def test_rejects_duplicate_account(self):
        s=copy.deepcopy(self.valid);s['accounts'].append(copy.deepcopy(s['accounts'][0]))
        with self.assertRaises(InvalidSnapshot):validate(s)

    def test_rejects_missing_root_boolean(self):
        s=copy.deepcopy(self.valid);del s['accounts'][0]['root']['mfa_enabled']
        with self.assertRaises(InvalidSnapshot):validate(s)

    def test_rejects_invalid_world_ip(self):
        s=copy.deepcopy(self.valid);s['accounts'][0]['security_groups'][0]['inbound'][0]['cidr']='not-cidr'
        with self.assertRaises(InvalidSnapshot):validate(s)

    def test_rejects_reversed_ports(self):
        s=copy.deepcopy(self.valid);s['accounts'][0]['security_groups'][0]['inbound'][0]['from_port']=9999
        with self.assertRaises(InvalidSnapshot):validate(s)

    def test_rejects_malformed_policy_action(self):
        s=copy.deepcopy(self.valid);s['accounts'][0]['roles'][0]['policies'][0]['Action']=12
        with self.assertRaises(InvalidSnapshot):validate(s)


if __name__=='__main__':unittest.main()
