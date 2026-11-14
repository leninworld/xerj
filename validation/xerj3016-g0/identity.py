"""Actual execution identity guards and bounded Docker-only fixture controls."""
import copy,re

def environment(env,plan):
    checks=[env.get('RUNNER_ENVIRONMENT')=='github-hosted',env.get('GITHUB_REPOSITORY')=='leninworld/xerj',env.get('GITHUB_REF')=='refs/heads/'+plan['branch'],env.get('GITHUB_EVENT_NAME')=='push',env.get('GITHUB_ACTOR')=='leninworld',env.get('GITHUB_RUN_ATTEMPT')=='1',str(env.get('GITHUB_RUN_ID','')).isdigit()and int(env['GITHUB_RUN_ID'])>0,str(env.get('GITHUB_RUN_NUMBER','')).isdigit()and int(env['GITHUB_RUN_NUMBER'])>=1,re.fullmatch('[0-9a-f]{40}',env.get('GITHUB_SHA',''))is not None]
    if not all(checks):raise ValueError('EXACT_ONE_SHOT_EXECUTION_IDENTITY')

def metadata(data,env,plan):
    environment(env,plan)
    if not(data['id']==int(env['GITHUB_RUN_ID'])and data['run_attempt']==1 and data['event']=='push'and data['head_branch']==plan['branch']and data['head_sha']==env['GITHUB_SHA']and data['path']==plan['workflow_published_path']and data['actor']['login']=='leninworld'and type(data['run_number'])is int and data['run_number']==int(env['GITHUB_RUN_NUMBER'])):raise ValueError('EXACT_WORKFLOW_METADATA_IDENTITY')

def fixture():
    plan={'branch':'codex/synthetic-control','workflow_published_path':'.github/workflows/synthetic.yml'}
    env={'RUNNER_ENVIRONMENT':'github-hosted','GITHUB_REPOSITORY':'leninworld/xerj','GITHUB_REF':'refs/heads/'+plan['branch'],'GITHUB_EVENT_NAME':'push','GITHUB_ACTOR':'leninworld','GITHUB_RUN_ATTEMPT':'1','GITHUB_RUN_ID':'123','GITHUB_RUN_NUMBER':'101','GITHUB_SHA':'a'*40}
    d={'id':123,'run_attempt':1,'event':'push','head_branch':plan['branch'],'head_sha':'a'*40,'path':plan['workflow_published_path'],'actor':{'login':'leninworld'},'run_number':101};metadata(d,env,plan)
    positive=[]
    for number in ['1','2','101']:
        e=dict(env,GITHUB_RUN_NUMBER=number);v=dict(d,run_number=int(number));metadata(v,e,plan);positive.append(number)
    negatives=[]
    for key,value in [('GITHUB_RUN_NUMBER','0'),('GITHUB_RUN_NUMBER','-1'),('GITHUB_RUN_ATTEMPT','2'),('GITHUB_REF','refs/heads/main'),('GITHUB_ACTOR','other'),('GITHUB_EVENT_NAME','workflow_dispatch'),('GITHUB_SHA','bad')]:
        e=dict(env);e[key]=value
        try:environment(e,plan)
        except ValueError:negatives.append(key+':'+value)
        else:raise AssertionError('IDENTITY_NEGATIVE_ACCEPTED')
    for key,value in [('id',124),('run_number',102),('head_sha','b'*40),('path','.github/workflows/wrong.yml')]:
        v=copy.deepcopy(d);v[key]=value
        try:metadata(v,env,plan)
        except ValueError:negatives.append('metadata:'+key)
        else:raise AssertionError('METADATA_NEGATIVE_ACCEPTED')
    return {'globalRunNumberPositives':positive,'negativeControls':negatives,'actualGuardFunctionsUsed':True,'noProjectExecution':True}
