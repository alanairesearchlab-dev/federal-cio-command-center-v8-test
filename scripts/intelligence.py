#!/usr/bin/env python3
"""Derive explainable public-source intelligence from previously collected JSON. No AI API."""
import json, pathlib, datetime, re, hashlib, collections, email.utils
ROOT=pathlib.Path(__file__).resolve().parents[1]; DATA=ROOT/'data'
NOW=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')
def read(name,default):
 try:return json.loads((DATA/name).read_text(encoding='utf-8'))
 except (OSError,ValueError):return default
def save(name,obj):(DATA/name).write_text(json.dumps(obj,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
def dt(s):
 try:return datetime.datetime.fromisoformat(str(s).replace('Z','+00:00')).astimezone(datetime.timezone.utc)
 except Exception:
  try:return email.utils.parsedate_to_datetime(str(s)).astimezone(datetime.timezone.utc)
  except Exception:return None
def clean(s):return re.sub(r'\s+',' ',str(s or '')).strip()
def key(s):return hashlib.sha256(s.encode()).hexdigest()[:16]
feed=read('security-feeds.json',{}); kev=read('kev.json',{}); register=read('federal-register.json',{}); status=read('status.json',{})
records=[]
POLICY_TERMS={'Cybersecurity':r'cybersecurity|cyber security|zero trust|incident reporting|fisma|nist|ransomware|information security', 'Artificial intelligence':r'artificial intelligence|\bai\b|machine learning|deepseek|automated decision', 'Privacy and data':r'privacy|personal data|data protection|records management|data governance', 'Federal IT and cloud':r'information technology|cloud computing|digital service|software|it modernization|information system|digital government', 'Acquisition':r'procurement|acquisition|federal acquisition|supply chain|contractor|far council'}
def policy_topics(title,abstract):
 text=(title+' '+abstract).lower()
 return [topic for topic,pattern in POLICY_TERMS.items() if re.search(pattern,text)]
def security_signals(title,summary):
 text=(title+' '+summary).lower(); signals=[]
 if re.search(r'\b(actively exploited|active exploitation|exploited in the wild|exploitation observed|under active exploitation)\b',text):signals.append('Reported active exploitation')
 if re.search(r'\b(zero.day|zero day)\b',text):signals.append('Zero-day reporting')
 if re.search(r'\b(critical|cvss 10|cvss 9\.)\b',text) and re.search(r'vulnerab|flaw|rce|remote code execution',text):signals.append('Critical vulnerability reporting')
 if re.search(r'\b(emergency patch|emergency update|patch immediately|urgent patch|emergency directive)\b',text):signals.append('Urgent remediation reporting')
 if re.search(r'\b(supply.chain attack|compromised package|malicious package)\b',text):signals.append('Software supply-chain incident')
 return signals

for i in feed.get('items',[]):
 url=clean(i.get('url')); title=clean(i.get('title'))
 if not url.startswith('https://') or not title:continue
 official=i.get('kind')=='official'; text=(title+' '+clean(i.get('summary'))).lower()
 reasons=security_signals(title,i.get('summary',''))
 if official:reasons.insert(0,'Official CISA advisory source')
 # Actionable security indicators only: avoid generic ransomware or law-enforcement keywords.
 tier='Attention' if any(x in reasons for x in ('Reported active exploitation','Zero-day reporting','Urgent remediation reporting')) else ('Monitor' if reasons or official else 'Informational')
 records.append(dict(id=key(url.split('?')[0]),type='advisory' if official else 'news',title=title[:240],url=url,source=clean(i.get('source')),published=clean(i.get('published')),observed_at=feed.get('retrieved_at'),topic='Cybersecurity',tier=tier,reasons=reasons,cves=sorted(set(re.findall(r'CVE-\d{4}-\d{4,}',title+' '+clean(i.get('summary')),re.I))),summary=clean(i.get('summary'))[:350]))
for i in register.get('items',[]):
 url=clean(i.get('url'));title=clean(i.get('title'))
 if not url.startswith('https://www.federalregister.gov/') or not title:continue
 topics=policy_topics(title,clean(i.get('abstract')))
 records.append(dict(id=key(url),type='policy',title=title[:240],url=url,source='Federal Register',published=clean(i.get('date')),observed_at=register.get('retrieved_at'),topic='Federal policy',tier='Monitor' if topics else 'Informational',reasons=['Topic relevance based on public document text; applicability not assessed'] if topics else ['No federal IT topic keyword match'],policy_topics=topics,policy_relevant=bool(topics),document_type=clean(i.get('type')),agency=clean(i.get('agency')),abstract=clean(i.get('abstract'))[:600]))
for i in kev.get('items',[]):
 cve=clean(i.get('cve')); title=clean(i.get('name'))
 if not re.fullmatch(r'CVE-\d{4}-\d{4,}',cve):continue
 records.append(dict(id=key(cve),type='kev',title=cve+' · '+title,url='https://nvd.nist.gov/vuln/detail/'+cve,source='CISA KEV',published=clean(i.get('added')),observed_at=kev.get('retrieved_at'),topic='Known exploited vulnerability',tier='Monitor',reasons=['Listed in CISA Known Exploited Vulnerabilities catalog; applicability not assessed'],vendor=clean(i.get('vendor')),product=clean(i.get('product')),cve=cve,due=clean(i.get('due')),action=clean(i.get('action')),ransomware=clean(i.get('ransomware'))))
# Snapshot comparisons are based on observed public records, not assertions of legal supersession.
previous=read('intelligence.json',{}); prior_ids={r.get('id') for r in previous.get('records',[])}
for r in records:r['new_since_previous']=bool(prior_ids) and r['id'] not in prior_ids
seen=read('intelligence-seen.json',{}); seen_ids=set(seen.get('ids',[]))
for r in records:r['first_observed_this_run']=bool(seen_ids) and r['id'] not in seen_ids
save('intelligence-seen.json',{'updated_at':NOW,'ids':sorted(seen_ids|{r['id'] for r in records})[-50000:]})
# Correlate explicit CVEs across news, advisories, and the authoritative KEV catalog.
by_cve=collections.defaultdict(list)
kev_ids={r['cve']:r['id'] for r in records if r['type']=='kev'}
for r in records:
 if r['type'] in ('advisory','news'):
  for cve in set(r.get('cves',[])):
   by_cve[cve.upper()].append(r['id'])
correlations=[]
for cve,ids in by_cve.items():
 if cve in kev_ids or len(ids)>=2:
  correlations.append({'cve':cve,'record_ids':ids,'count':len(ids),'in_kev':cve in kev_ids,'kev_record_id':kev_ids.get(cve)})
correlations.sort(key=lambda x:(not x['in_kev'],-x['count'],x['cve']))
source_counts=collections.Counter(r['source'] for r in records if r['type'] in ('news','advisory'))
new_policy=[r for r in records if r['type']=='policy' and r['first_observed_this_run']]
new_security=[r for r in records if r['type'] in ('news','advisory') and r['first_observed_this_run']]
result={'version':'8.2','generated_at':NOW,'methodology':'Deterministic public-source aggregation. Attention tiers are keyword heuristics, not verified severity, legal applicability, organizational exposure, or AI analysis. First observed is relative to locally retained collection history.','records':records,'correlations':correlations[:35],'source_counts':dict(source_counts),'summary':{'total':len(records),'new_kev':sum(r['type']=='kev' and r['first_observed_this_run'] for r in records),'relevant_policy':sum(r['type']=='policy' and r['policy_relevant'] for r in records),'attention':sum(r['tier']=='Attention' for r in records),'new_security':len(new_security),'new_policy':len(new_policy),'cve_correlations':len(correlations),'comparison_available':bool(seen_ids)},'sources_status':status.get('sources',{})}
save('intelligence.json',result)
print('Intelligence records:',len(records),'attention:',result['summary']['attention'])
