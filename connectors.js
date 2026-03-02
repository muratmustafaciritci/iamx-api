import fetch from 'node-fetch';
import crypto from 'crypto';
const sha=(s)=>crypto.createHash('sha1').update(s).digest('hex');

export async function runDomain(target){
  const val=target.value; const out=[];
  const types=['A','AAAA','CNAME','MX','NS','TXT'];
  for(const t of types){
    const url=`https://dns.google/resolve?name=${encodeURIComponent(val)}&type=${t}`;
    const r=await fetch(url,{headers:{accept:'application/json'}}).catch(()=>null);
    if(!r||!r.ok) continue;
    const j=await r.json().catch(()=>null); if(!j) continue;
    const ans=(j.Answer||[]).map(a=>a.data).slice(0,20);
    if(ans.length){
      out.push({source:'dns',severity:'info',title:`DNS ${t}`,details:ans.join('\n'),dedupe_key:sha([target.id,'dns',t,ans.join(',')].join('|'))});
    }
  }
  // SPF/DMARC
  const txtUrl=`https://dns.google/resolve?name=${encodeURIComponent(val)}&type=TXT`;
  const txt=await fetch(txtUrl).then(r=>r.json()).catch(()=>({}));
  const txtAns=(txt.Answer||[]).map(a=>String(a.data).replace(/^"|"$/g,''));
  const hasSpf=txtAns.some(s=>s.toLowerCase().includes('v=spf1'));
  out.push({source:'emailsec',severity:hasSpf?'info':'low',title:hasSpf?'SPF present':'SPF missing',details:hasSpf?txtAns.filter(s=>s.toLowerCase().includes('v=spf1')).join('\n'):'No v=spf1 TXT record found.',dedupe_key:sha([target.id,'spf',String(hasSpf)].join('|'))});
  const dmarcName=`_dmarc.${val}`;
  const dmarc=await fetch(`https://dns.google/resolve?name=${encodeURIComponent(dmarcName)}&type=TXT`).then(r=>r.json()).catch(()=>({}));
  const dmarcAns=(dmarc.Answer||[]).map(a=>String(a.data).replace(/^"|"$/g,''));
  const hasDmarc=dmarcAns.some(s=>s.toLowerCase().includes('v=dmarc1'));
  out.push({source:'emailsec',severity:hasDmarc?'info':'med',title:hasDmarc?'DMARC present':'DMARC missing',details:hasDmarc?dmarcAns.join('\n'):'No v=DMARC1 TXT record found at _dmarc.',dedupe_key:sha([target.id,'dmarc',String(hasDmarc)].join('|'))});
  // CT
  try{
    const ctRes=await fetch(`https://crt.sh/?q=${encodeURIComponent(val)}&output=json`,{headers:{'user-agent':'iamx/1.0'}});
    if(ctRes.ok){
      const ct=await ctRes.json();
      const names=[...new Set(ct.flatMap(x=>String(x.name_value||'').split('\n')))].slice(0,30);
      if(names.length){
        out.push({source:'ct',severity:'info',title:'Certificate Transparency names',details:names.join('\n'),dedupe_key:sha([target.id,'ct',names.slice(0,10).join(',')].join('|'))});
      }
    }
  }catch{}
  return out;
}

export async function runIP(target){
  const out=[]; const ip=target.value;
  try{
    const r=await fetch(`https://ipinfo.io/${encodeURIComponent(ip)}/json`,{headers:{accept:'application/json'}});
    if(r.ok){
      const j=await r.json();
      out.push({source:'ipinfo',severity:'info',title:'IP / ASN info',details:JSON.stringify(j,null,2),dedupe_key:sha([target.id,'ipinfo',j.org||'',j.country||''].join('|'))});
    }
  }catch{}
  return out;
}

export async function runKeyword(target){
  const out=[]; const q=target.value;
  try{
    const r=await fetch(`https://hn.algolia.com/api/v1/search?query=${encodeURIComponent(q)}&tags=story`);
    if(r.ok){
      const j=await r.json();
      const hits=(j.hits||[]).slice(0,5).map(h=>`${h.title}\n${h.url||''}`.trim()).join('\n\n');
      if(hits){
        out.push({source:'hn',severity:'info',title:'Keyword mentions (HN sample)',details:hits,dedupe_key:sha([target.id,'hn',String((j.hits||[])[0]?.objectID||'')].join('|'))});
      }
    }
  }catch{}
  return out;
}

export async function runX(target){
  const out=[]; const u=String(target.value).replace(/^@/,'');
  const url=`https://x.com/${encodeURIComponent(u)}`;
  try{
    const r=await fetch(url,{redirect:'follow',headers:{'user-agent':'Mozilla/5.0'}});
    const text=await r.text();
    let status='ACTIVE';
    if(r.status===404) status='NOT_FOUND';
    const t=text.toLowerCase();
    if(t.includes('account suspended')||t.includes('suspended')) status='SUSPENDED';
    if(t.includes("doesn’t exist")||t.includes("doesn't exist")) status='NOT_FOUND';
    out.push({source:'x',severity:status==='ACTIVE'?'info':(status==='SUSPENDED'?'high':'med'),title:`X status: ${status}`,details:`${url}\nHTTP ${r.status}`,dedupe_key:sha([target.id,'xstatus',status].join('|'))});
  }catch(e){
    out.push({source:'x',severity:'low',title:'X status: ERROR',details:String(e),dedupe_key:sha([target.id,'xstatus','ERROR'].join('|'))});
  }
  return out;
}
