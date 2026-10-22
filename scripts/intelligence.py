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
for i in feed.get('items',[]):
 url=clean(i.get('url')); title=clean(i.get('title'))
 if not url.startswith('https://') or not title:continue
 official=i.get('kind')=='official'; text=(title+' '+clean(i.get('summary'))).lower()
 reasons=[]
 if official:reasons.append('Official CISA advisory source')
 if re.search(r'\b(actively exploited|active exploitation|exploited in the wild)\b',text):reasons.append('Source mentions active exploitation')
 if re.search(r'\b(immediate patch|patch immediately|urgent patch|emergency directive|take offline|disconnect from the internet)\b',text):reasons.append('Source contains urgent-action language')
 if re.search(r'\b(zero.day|critical vulnerabilit|ransomware)\b',text):reasons.append('Source contains an attention keyword')
 tier='Attention' if len(reasons)>1 or (not official and len(reasons)>0) else ('Monitor' if reasons else 'Informational')
 records.append(dict(id=key(url.split('?')[0]),type='advisory' if official else 'news',title=title[:240],url=url,source=clean(i.get('source')),published=clean(i.get('published')),observed_at=feed.get('retrieved_at'),topic='Cybersecurity',tier=tier,reasons=reasons,summary=clean(i.get('summary'))[:350]))
for i in register.get('items',[]):
 url=clean(i.get('url'));title=clean(i.get('title'))
 if not url.startswith('https://www.federalregister.gov/') or not title:continue
 records.append(dict(id=key(url),type='policy',title=title[:240],url=url,source='Federal Register',published=clean(i.get('date')),observed_at=register.get('retrieved_at'),topic='Federal policy',tier='Monitor' if i.get('type') in ('Rule','Presidential Document') else 'Informational',reasons=['Federal Register document; applicability not assessed'],document_type=clean(i.get('type')),agency=clean(i.get('agency'))))
for i in kev.get('items',[]):
 cve=clean(i.get('cve')); title=clean(i.get('name'))
 if not re.fullmatch(r'CVE-\d{4}-\d{4,}',cve):continue
 records.append(dict(id=key(cve),type='kev',title=cve+' · '+title,url='https://nvd.nist.gov/vuln/detail/'+cve,source='CISA KEV',published=clean(i.get('added')),observed_at=kev.get('retrieved_at'),topic='Known exploited vulnerability',tier='Monitor',reasons=['Listed in CISA Known Exploited Vulnerabilities catalog; applicability not assessed'],vendor=clean(i.get('vendor')),product=clean(i.get('product')),cve=cve))
# Snapshot comparisons are based on observed public records, not assertions of legal supersession.
previous=read('intelligence.json',{}); prior_ids={r.get('id') for r in previous.get('records',[])}
for r in records:r['new_since_previous']=bool(prior_ids) and r['id'] not in prior_ids
seen=read('intelligence-seen.json',{}); seen_ids=set(seen.get('ids',[]))
for r in records:r['first_observed_this_run']=bool(seen_ids) and r['id'] not in seen_ids
save('intelligence-seen.json',{'updated_at':NOW,'ids':sorted(seen_ids|{r['id'] for r in records})[-50000:]})
# Group related articles by extracted CVE where available; no fuzzy semantic equivalence claims.
by_cve=collections.defaultdict(list)
for r in records:
 if r['type'] in ('advisory','news'):
  for cve in set(re.findall(r'CVE-\d{4}-\d{4,}',r['title']+' '+r.get('summary',''),re.I)):by_cve[cve.upper()].append(r['id'])
correlations=[{'cve':cve,'record_ids':ids,'count':len(ids)} for cve,ids in by_cve.items() if len(ids)>=2]
correlations.sort(key=lambda x:x['count'],reverse=True)
source_counts=collections.Counter(r['source'] for r in records if r['type'] in ('news','advisory'))
new_policy=[r for r in records if r['type']=='policy' and r['first_observed_this_run']]
new_security=[r for r in records if r['type'] in ('news','advisory') and r['first_observed_this_run']]
result={'version':'8.0','generated_at':NOW,'methodology':'Deterministic public-source aggregation. Attention tiers are keyword heuristics, not verified severity, legal applicability, organizational exposure, or AI analysis. First observed is relative to locally retained collection history.','records':records,'correlations':correlations[:35],'source_counts':dict(source_counts),'summary':{'total':len(records),'attention':sum(r['tier']=='Attention' for r in records),'new_security':len(new_security),'new_policy':len(new_policy),'cve_correlations':len(correlations),'comparison_available':bool(seen_ids)},'sources_status':status.get('sources',{})}
save('intelligence.json',result)
print('Intelligence records:',len(records),'attention:',result['summary']['attention'])
