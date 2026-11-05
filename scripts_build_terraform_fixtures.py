"""Build deterministic hand-authored, Terraform-JSON-shaped synthetic examples."""
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parent


def res(kind, name, values):
    return {'address':f'{kind}.{name}', 'mode':'managed','type':kind,'name':name,
            'provider_name':'registry.terraform.io/hashicorp/aws','values':values,
            'sensitive_values':{}}


def policy(*statements):
    return json.dumps({'Version':'2012-10-17','Statement':list(statements)},sort_keys=True,separators=(',',':'))


def plan(hardened):
    bucket='lab-sensitive-records'
    root=[
        res('aws_iam_role','support_access',{'name':'lab-support-role',
            'assume_role_policy':policy({'Effect':'Allow','Action':'sts:AssumeRole',
                'Principal':{'AWS':'arn:aws:iam::111111111111:role/approved-support'}}
                if hardened else {'Effect':'Allow','Action':'sts:AssumeRole','Principal':{'AWS':'*'}})}),
        res('aws_iam_role','conditional_partner',{'name':'lab-conditional-partner',
            'assume_role_policy':policy({'Effect':'Allow','Action':'sts:AssumeRole',
                'Principal':{'AWS':'*'},'Condition':{'StringEquals':{'sts:ExternalId':'lab-approved-external-id'}}})}),
        res('aws_iam_policy','build_permissions',{'name':'lab-build-permissions',
            'policy':policy({'Effect':'Allow','Action':['s3:PutObject','s3:GetObject'],
                   'Resource':'arn:aws:s3:::lab-build-artifacts/*'} if hardened else
                   {'Effect':'Allow','Action':'*','Resource':'*'})}),
        res('aws_iam_role_policy','reporting_permissions',{'name':'lab-reporting',
            'policy':policy({'Effect':'Allow','Action':['s3:GetObject'],
                   'Resource':'arn:aws:s3:::lab-reporting/*'} if hardened else
                   {'Effect':'Allow','Action':'s3:*','Resource':'*'})}),
        res('aws_iam_policy','explicit_deny_context',{'name':'lab-no-access',
            'policy':policy({'Effect':'Allow','Action':'*','Resource':'*'},
                            {'Effect':'Deny','Action':'*','Resource':'*'})}),
        res('aws_s3_bucket','records',{'bucket':bucket}),
        res('aws_s3_bucket_public_access_block','records',{
            'bucket':bucket,**{k:(True if hardened else False) for k in (
            'block_public_acls','ignore_public_acls','block_public_policy','restrict_public_buckets')}}),
        res('aws_security_group','web',{'name':'lab-web', 'ingress':[
            {'protocol':'tcp','from_port':443,'to_port':443,
             'cidr_blocks':['0.0.0.0/0'],'ipv6_cidr_blocks':[]},
            {'protocol':'tcp','from_port':22,'to_port':22,
             'cidr_blocks':['10.0.0.0/8'] if hardened else ['0.0.0.0/0'],
             'ipv6_cidr_blocks':[]},
            {'protocol':'tcp','from_port':5432,'to_port':5432,
             'cidr_blocks':['10.0.0.0/8'] if hardened else ['0.0.0.0/0'],
             'ipv6_cidr_blocks':[]},
        ]}),
        res('aws_cloudtrail','organization_audit',{'name':'lab-organization-trail',
            'is_multi_region_trail':True if hardened else False,
            'enable_log_file_validation':True if hardened else False}),
        res('aws_config_configuration_recorder','recorder',{'name':'lab-recorder',
            'recording_group':[{'all_supported':True if hardened else False}]}),
    ]
    # Nested module tests demonstrate recursive traversal without evaluating HCL.
    nested=[res('aws_vpc_security_group_ingress_rule','database',{
        'ip_protocol':'tcp','from_port':5432,'to_port':5432,
        'cidr_ipv4':'10.11.0.0/16' if hardened else '0.0.0.0/0',
        'cidr_ipv6':None})]
    for item in nested:
        item['address']='module.application.'+item['address']
    # A resource created with unknown policy content is review-only, never a pass.
    undecided = res('aws_iam_role','future_partner',{
        'name':'lab-future-partner','assume_role_policy':None})
    undecided['address']='module.application.'+undecided['address']
    nested.append(undecided)
    all_items=root+nested
    changes=[{'address':r['address'],'mode':'managed','type':r['type'],
              'name':r['name'],'change':{'actions':['update'],
                'before':None,'after':r['values'],
                'after_unknown':{'assume_role_policy':True} if r['address'].endswith('future_partner') else {}}}
             for r in all_items]
    return {'format_version':'1.2','terraform_version':'1.9.0',
            'lab_metadata':{'synthetic':True,
                'provenance':'Hand-authored Terraform JSON format example; NOT terraform show output'},
            'planned_values':{'root_module':{'resources':root,
                'child_modules':[{'address':'module.application','resources':nested}]}},
            'resource_changes':changes}


if __name__=='__main__':
    dest=ROOT/'terraform'
    dest.mkdir(exist_ok=True)
    for hard,label in ((False,'vulnerable'),(True,'hardened')):
        (dest/f'{label}.plan.json').write_text(json.dumps(plan(hard),indent=2)+'\n',encoding='utf-8')
    print('Generated synthetic Terraform JSON-shaped fixtures (not Terraform generated).')
