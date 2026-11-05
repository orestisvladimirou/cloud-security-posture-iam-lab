import copy
import json
import tempfile
import unittest
from pathlib import Path

from cloudguard.terraform_plan import InvalidPlan, load_plan, scan_plan, validate_plan
from cloudguard.sarif import from_plan
from cloudguard.cli import main

ROOT = Path(__file__).resolve().parents[1]


class TerraformPlanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v = load_plan(ROOT/'terraform/vulnerable.plan.json')
        cls.h = load_plan(ROOT/'terraform/hardened.plan.json')

    def copy(self, plan=None):
        return copy.deepcopy(plan if plan is not None else self.h)

    def find(self, plan):
        return scan_plan(plan)

    def resource(self, plan, addr):
        for r in plan['planned_values']['root_module']['resources']:
            if r['address'] == addr: return r
        for module in plan['planned_values']['root_module']['child_modules']:
            for r in module['resources']:
                if r['address'] == addr: return r
        raise KeyError(addr)

    def test_vulnerable_and_hardened_counts(self):
        self.assertEqual(self.find(self.v)['counts'],{'Critical':1,'High':6,'Medium':3,'Low':0})
        self.assertEqual(self.find(self.h)['counts'],{'Critical':0,'High':0,'Medium':0,'Low':0})
        self.assertEqual(len(self.find(self.h)['manual_reviews']),3)

    def test_hardened_is_not_declared_safe_when_context_unknown(self):
        r = self.find(self.h)
        self.assertTrue(r['manual_reviews'])
        self.assertTrue(any('unknown' in x.issue.lower() for x in r['manual_reviews']))

    def test_iam_wildcard_trust_is_flagged(self):
        self.assertIn('TF-IAM-001',{x.rule_id for x in self.find(self.v)['findings']})

    def test_conditioned_trust_gets_review_not_unconditional_risk(self):
        r = self.find(self.h)
        self.assertIn('Wildcard trust principal is conditioned',[x.issue for x in r['manual_reviews']])
        self.assertNotIn('TF-IAM-001',{x.rule_id for x in r['findings']})

    def test_global_deny_suppresses_ineffective_wildcard_positive(self):
        p=self.copy()
        r=self.find(p)
        addr='aws_iam_policy.explicit_deny_context'
        self.assertFalse(any(x.address==addr for x in r['findings']))
        self.assertTrue(any(x.address==addr for x in r['manual_reviews']))

    def test_conditioned_deny_does_not_suppress_unconditional_admin_allow(self):
        p=self.copy()
        res=self.resource(p,'aws_iam_policy.build_permissions')
        res['values']['policy']=json.dumps({'Statement':[{'Effect':'Allow','Action':'*','Resource':'*'},
            {'Effect':'Deny','Action':'*','Resource':'*','Condition':{'StringEquals':{'aws:PrincipalTag/lab':'no'}}}]})
        result=self.find(p)
        self.assertIn('TF-IAM-002',{x.rule_id for x in result['findings']})
        self.assertTrue(any('Conditional Deny' in x.issue for x in result['manual_reviews']))

    def test_wildcard_service_policy_is_reviewable_pattern(self):
        self.assertIn('TF-IAM-003',{x.rule_id for x in self.find(self.v)['findings']})

    def test_s3_disabled_bpa_flag_detected(self):
        self.assertIn('TF-S3-001',{x.rule_id for x in self.find(self.v)['findings']})
        self.assertNotIn('TF-S3-001',{x.rule_id for x in self.find(self.h)['findings']})

    def test_s3_absent_bpa_is_unknown_not_auto_failure(self):
        p=self.copy()
        p['planned_values']['root_module']['resources']=[r for r in p['planned_values']['root_module']['resources']
            if r['type']!='aws_s3_bucket_public_access_block']
        result=self.find(p)
        self.assertTrue(any('not represented' in x.issue for x in result['manual_reviews']))
        self.assertFalse(any(x.rule_id=='TF-S3-001' for x in result['findings']))

    def test_world_open_ssh_and_database(self):
        rules=[x.rule_id for x in self.find(self.v)['findings']]
        self.assertIn('TF-NET-001',rules)
        self.assertEqual(rules.count('TF-NET-002'),2)

    def test_private_admin_and_public_https_no_flags(self):
        self.assertFalse(any(x.rule_id.startswith('TF-NET') for x in self.find(self.h)['findings']))

    def test_deleted_resources_are_not_scanned(self):
        p=self.copy(self.v)
        addr='aws_iam_role.support_access'
        next(x['change'] for x in p['resource_changes'] if x['address']==addr)['actions']=['delete']
        self.assertFalse(any(x.address==addr for x in self.find(p)['findings']))

    def test_after_unknown_is_manual_review_not_clean(self):
        p=self.copy(self.v)
        addr='aws_iam_role.support_access'
        next(x['change'] for x in p['resource_changes'] if x['address']==addr)['after_unknown']={'assume_role_policy':True}
        result=self.find(p)
        self.assertFalse(any(x.address==addr for x in result['findings']))
        self.assertTrue(any(x.address==addr for x in result['manual_reviews']))

    def test_rejects_live_plan_marker_absent(self):
        p=self.copy()
        del p['lab_metadata']
        with self.assertRaises(InvalidPlan):validate_plan(p)

    def test_rejects_wrong_format_major_version(self):
        p=self.copy();p['format_version']='2.0'
        with self.assertRaises(InvalidPlan):validate_plan(p)

    def test_rejects_duplicate_resource_addresses(self):
        p=self.copy();p['planned_values']['root_module']['resources'].append(copy.deepcopy(p['planned_values']['root_module']['resources'][0]))
        with self.assertRaises(InvalidPlan):validate_plan(p)

    def test_rejects_malformed_policy(self):
        p=self.copy()
        self.resource(p,'aws_iam_role.support_access')['values']['assume_role_policy']='not-json'
        with self.assertRaises(InvalidPlan):self.find(p)

    def test_sarif_has_distinct_rule_fingerprints(self):
        sarif=from_plan(self.find(self.v),'terraform/vulnerable.plan.json')
        self.assertEqual(sarif['version'],'2.1.0')
        run=sarif['runs'][0]
        self.assertEqual(len(run['results']),10)
        self.assertEqual(len({x['partialFingerprints']['resourceRuleHash'] for x in run['results']}),10)
        self.assertFalse(run['properties']['liveAwsInspected'])
        self.assertTrue(all(x['locations'][0]['physicalLocation']['region']['startLine']==1 for x in run['results']))

    def test_cli_exit_codes_and_output(self):
        with tempfile.TemporaryDirectory() as td:
            f=Path(td)/'out.json'
            self.assertEqual(main(['plan',str(ROOT/'terraform/vulnerable.plan.json'), '--format','json','--output',str(f),'--fail-on','Critical']),2)
            self.assertEqual(json.loads(f.read_text())['counts']['Critical'],1)
            self.assertEqual(main(['plan',str(ROOT/'terraform/hardened.plan.json'), '--output',str(f),'--fail-on','High']),0)
            self.assertEqual(main(['plan',str(ROOT/'terraform/hardened.plan.json'), '--output',str(f),'--fail-on-review']),4)
            self.assertEqual(main(['plan',str(f),'--output',str(Path(td)/'err')]),3)


if __name__ == '__main__':unittest.main()
