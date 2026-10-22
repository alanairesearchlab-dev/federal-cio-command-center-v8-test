#!/usr/bin/env python3
"""Collect PUBLIC federal intelligence. No credentials, no agency data."""
import json, pathlib, urllib.request, datetime, os, xml.etree.ElementTree as ET, re, html, hashlib
from urllib.parse import urlparse
from collections import Counter
ROOT=pathlib.Path(__file__).resolve().parents[1]
OUT=ROOT/'data'; OUT.mkdir(exist_ok=True)
NOW=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')
URLS={
 'kev':'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
 'register':'https://www.federalregister.gov/api/v1/documents.json?per_page=100&order=newest&conditions%5Bterm%5D=cybersecurity%20OR%20artificial%20intelligence%20OR%20information%20technology'
}
def get(url):
 req=urllib.request.Request(url,headers={'User-Agent':'PublicCIOResearchDashboard/1.0 (public data; no auth)','Accept':'application/json'})
 with urllib.request.urlopen(req,timeout=35) as r: return json.load(r)
def read(name,default):
 try:return json.loads((OUT/name).read_text())
 except (OSError,ValueError):return default
def write(name,obj):
 (OUT/name).write_text(json.dumps(obj,ensure_ascii=False,indent=2)+'\n')
previous_status=read('status.json',{}).get('sources',{})
status={'updated_at':NOW,'sources':{}}
def record_source(name, ok, count=None, error=None):
    prior=previous_status.get(name,{})
    last_success = NOW if ok else (prior.get('last_success_at') or (prior.get('retrieved_at') if prior.get('ok') else None))
    entry={'ok':ok,'checked_at':NOW,'last_success_at':last_success}
    if count is not None:entry['count']=count
    if error is not None:entry['error']=str(error)
    status['sources'][name]=entry

try:
 raw=get(URLS['kev']); vulns=raw.get('vulnerabilities',[])
 if not isinstance(vulns,list) or not vulns:raise ValueError('No KEV records returned')
 items=[{'cve':str(v.get('cveID','')),'vendor':str(v.get('vendorProject','')),'product':str(v.get('product','')),'name':str(v.get('vulnerabilityName','')),'added':str(v.get('dateAdded','')),'due':str(v.get('dueDate','')),'ransomware':str(v.get('knownRansomwareCampaignUse','')),'action':str(v.get('requiredAction','')),'notes':str(v.get('notes',''))} for v in vulns]
 items.sort(key=lambda x:(x['added'],x['cve']),reverse=True)
 previous=read('kev.json',{}).get('items',[])
 previous_ids={x.get('cve') for x in previous}
 new_records=[x for x in items if x['cve'] not in previous_ids] if previous else []
 vendors=Counter(x['vendor'] for x in items)
 write('insights.json',{'retrieved_at':NOW,'comparison_available':bool(previous),'new_since_previous_collection':new_records[:100],'new_count':len(new_records),'top_vendors':[{'name':k,'count':v} for k,v in vendors.most_common(30)],'note':'New means first seen by this collector, not necessarily newly published or exploited.'})
 write('kev.json',{'retrieved_at':NOW,'source':URLS['kev'],'count':len(items),'items':items})
 history=read('kev-history.json',[])
 day=NOW[:10]; entry={'date':day,'count':len(items)}
 history=[h for h in history if h.get('date')!=day]+[entry]
 write('kev-history.json',history[-365:])
 record_source('kev',True,len(items))
except Exception as e:
 record_source('kev',False,error=e)
try:
 previous_register=read('federal-register.json',{}).get('items',[])
 raw=get(URLS['register']); docs=raw.get('results',[])
 if not isinstance(docs,list):raise ValueError('Invalid Federal Register response')
 items=[{'title':str(d.get('title','')),'date':str(d.get('publication_date','')),'url':str(d.get('html_url','')),'type':str(d.get('type','')),'agency':', '.join(a.get('name','') for a in d.get('agencies',[]) if isinstance(a,dict)),'abstract':str(d.get('abstract') or '')[:600]} for d in docs]
 write('federal-register.json',{'retrieved_at':NOW,'source':URLS['register'],'count':len(items),'items':items})
 record_source('register',True,len(items))
except Exception as e:
 record_source('register',False,error=e)
# Public Federal Register change detection. Do not compare stale data after a failed fetch.
try:
 if not status['sources']['register']['ok']:raise RuntimeError('Skipped policy comparison because Federal Register retrieval failed')
 current=read('federal-register.json',{}).get('items',[])
 # Compare stable document URLs against the prior successful snapshot saved separately.
 prior=read('register-seen.json',{}).get('urls',[])
 seen=set(prior)
 fresh=[d for d in current if d.get('url') and d['url'] not in seen] if prior else []
 write('policy-insights.json',{'retrieved_at':NOW,'comparison_available':bool(prior),'new_count':len(fresh),'new_documents':fresh[:35],'note':'New means first observed in the current matching search results, not necessarily new binding federal policy. Search results may include notices, proposed rules and unrelated documents.'})
 # Retain identifiers over time to avoid treating older search results as new.
 combined=list(dict.fromkeys(prior+[d['url'] for d in current if d.get('url')]))
 write('register-seen.json',{'retrieved_at':NOW,'urls':combined[-10000:]})
 record_source('policy_insights',True,len(fresh))
except Exception as e:
 record_source('policy_insights',False,error=e)

# Public RSS/Atom intelligence. A feed failure never deletes the last successful snapshot.
FEEDS={
 'cisa_all':('CISA Advisories','official','https://www.cisa.gov/cybersecurity-advisories/all.xml'),
 'cisa_alerts':('CISA Alerts','official','https://www.cisa.gov/cybersecurity-advisories/alerts.xml'),
 'bleepingcomputer':('BleepingComputer','news','https://www.bleepingcomputer.com/feed/'),
 'krebs':('Krebs on Security','news','https://krebsonsecurity.com/feed/'),
 'hackernews':('The Hacker News','news','https://feeds.feedburner.com/TheHackersNews'),
}
def feed_text(el,name):
 node=el.find(name)
 return ''.join(node.itertext()).strip() if node is not None else ''
def strip_markup(value):
 return re.sub(r'\s+',' ',html.unescape(re.sub(r'<[^>]+>',' ',value or ''))).strip()[:420]
def parse_feed(payload, source, kind):
 root=ET.fromstring(payload)
 items=[]
 # RSS and Atom are supported without third-party packages.
 if root.tag.endswith('rss') or root.find('channel') is not None:
  nodes=root.findall('./channel/item')
  for el in nodes:
   title=feed_text(el,'title'); link=feed_text(el,'link'); date=feed_text(el,'pubDate')
   desc=strip_markup(feed_text(el,'description'))
   if title and link:items.append({'title':title[:240],'url':link,'published':date,'summary':desc,'source':source,'kind':kind})
 else:
  ns='{http://www.w3.org/2005/Atom}'
  for el in root.findall(ns+'entry'):
   title=feed_text(el,ns+'title'); date=feed_text(el,ns+'published') or feed_text(el,ns+'updated')
   desc=strip_markup(feed_text(el,ns+'summary') or feed_text(el,ns+'content'))
   links=[n.get('href','') for n in el.findall(ns+'link') if n.get('rel','alternate')=='alternate']
   link=(links or [n.get('href','') for n in el.findall(ns+'link')])[:1]
   if title and link:items.append({'title':title[:240],'url':link[0],'published':date,'summary':desc,'source':source,'kind':kind})
 return items[:65]
def urgency(item):
 # A keyword flag is a research cue, never an official severity designation.
 t=(item['title']+' '+item['summary']).lower()
 terms=['immediate patch','patch immediately','urgent patch','actively exploited','active exploitation','zero-day','zero day','critical vulnerabilit','emergency directive','take offline','disconnect from the internet']
 return any(x in t for x in terms)
feed_items=[]; successes=0
for key,(source,kind,url) in FEEDS.items():
 try:
  req=urllib.request.Request(url,headers={'User-Agent':'PublicCIOResearchDashboard/1.1 (public feeds; no auth)','Accept':'application/rss+xml, application/atom+xml, application/xml, text/xml'})
  with urllib.request.urlopen(req,timeout=25) as response:
   payload=response.read(2_500_000)
  items=parse_feed(payload,source,kind)
  if not items:raise ValueError('No RSS/Atom entries returned')
  # Restrict article URLs to HTTPS. Titles and summaries are rendered as escaped text.
  items=[i for i in items if urlparse(i['url']).scheme=='https']
  if not items:raise ValueError('No HTTPS article links')
  feed_items.extend(items);successes+=1
  record_source(key,True,len(items))
 except Exception as e:
  record_source(key,False,error=e)
if successes:
 old=read('security-feeds.json',{}).get('items',[])
 # Keep previous source items when that source temporarily fails.
 healthy={source for key,(source,kind,url) in FEEDS.items() if status['sources'][key]['ok']}
 feed_items.extend(i for i in old if i.get('source') not in healthy)
 unique={}
 for i in feed_items:
  k=i['url'].split('?')[0].rstrip('/')
  if k not in unique:unique[k]=i
 from email.utils import parsedate_to_datetime
 def timestamp(i):
  try:return parsedate_to_datetime(i['published']).timestamp()
  except Exception:
   try:return datetime.datetime.fromisoformat(i['published'].replace('Z','+00:00')).timestamp()
   except Exception:return 0
 items=sorted(unique.values(),key=timestamp,reverse=True)[:180]
 for i in items:i['attention_keyword']=urgency(i)
 write('security-feeds.json',{'retrieved_at':NOW,'sources':list(FEEDS),'items':items,'note':'Attention flags are automated keyword matches, not CISA severity ratings or environment-specific findings.'})
record_source('security_feeds',bool(successes),len(feed_items) if successes else None,error=None if successes else 'All security RSS sources failed; previous snapshot retained')

write('status.json',status)
print(json.dumps(status,indent=2))
if not (status['sources']['kev']['ok'] or status['sources']['register']['ok']):raise SystemExit('All public feeds failed; keeping previously collected data')
