(function () {
  'use strict';
  var state=document.getElementById('state'),log=document.getElementById('log'),start=document.getElementById('start'),save=document.getElementById('save');
  var suite=/\/phase2$/.test(location.pathname||'')||/(?:^|[?&])suite=phase2(?:&|$)/.test(location.search)?'phase2':'baseline';
  if(/\/context$/.test(location.pathname||''))suite='context';
  if(/\/messaging$/.test(location.pathname||''))suite='messaging';
  if(/\/ssvprobe$/.test(location.pathname||''))suite='ssvprobe';
  var tests=suite==='baseline'?window.ResearchTests:window.ResearchSuites[suite];
  var active=false,run=null,seq=0,queue=Promise.resolve(),localEvents=[],timer=null;
  var ua=navigator.userAgent||'',isPS5=/PlayStation 5/.test(ua),fwMatch=/PlayStation 5\/(\d+\.\d+)/.exec(ua);
  document.getElementById('origin').value=isPS5?'ps5_hardware_reported':'desktop_simulation';
  document.getElementById('firmware').value=isPS5&&fwMatch?fwMatch[1]:'';
  document.getElementById('device-summary').textContent=isPS5?'PS5 browser / reported firmware '+(fwMatch?fwMatch[1]:'unknown'):'Desktop browser / console tests';
  var labels={baseline:'Baseline',phase2:'Compatibility',context:'Worker context',messaging:'Messaging',ssvprobe:'Clone probe'};
  var descriptions={baseline:'Check essential browser features, memory views and network access.',phase2:'Explore JavaScript, WebAssembly availability, timing and browser APIs.',context:'Compare browser features in the page and a background worker.',messaging:'Check worker messages, buffer copies and transferred data.',ssvprobe:'Compare duplicate-reference roundtrips for small and larger BigInt graphs.'};
  var completed=0,passed=0,unavailable=0,issues=0;
  start.textContent='Start '+labels[suite].toLowerCase();
  document.getElementById('suite-title').textContent=labels[suite];
  document.getElementById('suite-description').textContent=descriptions[suite];
  document.getElementById('suite-meta').textContent=tests.length+' test'+(tests.length===1?'':'s');
  var selected=document.getElementById('nav-'+suite);
  if(selected&&selected.setAttribute)selected.setAttribute('aria-current','page');
  function badge(text){document.getElementById('session-badge').textContent=text;}
  function progress(message){
    document.getElementById('progress-text').textContent=message;
    var bar=document.getElementById('progress'),fill=document.getElementById('progress-fill');
    if(bar.setAttribute){bar.setAttribute('aria-valuemax',tests.length);bar.setAttribute('aria-valuenow',completed);}
    if(fill.style)fill.style.width=(completed/tests.length*100)+'%';
    document.getElementById('result-count').textContent=completed?completed+' / '+tests.length:tests.length+' test'+(tests.length===1?'':'s');
  }
  function totals(){return passed+' passed'+(unavailable?' / '+unavailable+' unavailable':'')+(issues?' / '+issues+' need review':'');}
  function readable(id){return id.replace(/_/g,' ').replace(/\b\w/g,function(c){return c.toUpperCase();});}
  function resultCard(result){
    if(!document.createElement)return;
    var row=document.createElement('div'),name=document.createElement('div'),time=document.createElement('small'),badge=document.createElement('span');
    row.className='result-row';name.className='result-name';name.textContent=readable(result.id);
    time.textContent=result.status==='UNSUPPORTED'?'Feature not exposed in this browser':result.status==='SKIPPED'?'Check skipped':result.status==='TIMEOUT'?'No result within the test deadline':result.status==='EXCEPTION'?'JavaScript exception captured':result.status==='UNEXPECTED_RESULT'?'Observed graph differs from the specification expectation':'Returned in '+result.elapsed_ms+' ms';name.appendChild(time);
    badge.className='result-badge '+result.status;badge.textContent=result.status==='UNSUPPORTED'?'UNAVAILABLE':result.status;
    row.appendChild(name);row.appendChild(badge);document.getElementById('results').appendChild(row);
  }
  progress('Ready when you are');
  // Directional keyboard events, when exposed by the browser. Pointer and native Tab remain available.
  if(document.addEventListener)document.addEventListener('keydown',function(e){
    if(e.altKey||e.ctrlKey||e.metaKey||e.shiftKey)return;
    var direction=e.key||({37:'ArrowLeft',38:'ArrowUp',39:'ArrowRight',40:'ArrowDown'})[e.keyCode];
    if(!/^Arrow(Left|Right|Up|Down)$/.test(direction))return;
    var current=document.activeElement;
    if(current&&/^(INPUT|SELECT|TEXTAREA)$/.test(current.tagName))return;
    var navIds=['nav-baseline','nav-phase2','nav-context','nav-messaging','nav-ssvprobe'],navIndex=current?navIds.indexOf(current.id):-1,target=null;
    if(navIndex>=0){
      if(direction==='ArrowLeft')target=document.getElementById(navIds[Math.max(0,navIndex-1)]);
      if(direction==='ArrowRight')target=document.getElementById(navIds[Math.min(4,navIndex+1)]);
      if(direction==='ArrowDown')target=start.disabled?document.getElementById('larger-text'):start;
    }else if(current&&(current.id==='start'||current.id==='larger-text')&&direction==='ArrowUp')target=selected;
    if(target){e.preventDefault();target.focus();return;}
    var candidates=document.querySelectorAll('a[href],button:not([disabled]),summary,input,select'),from=current&&current.getBoundingClientRect?current.getBoundingClientRect():null;
    if(!from)return;
    var x=from.left+from.width/2,y=from.top+from.height/2,best=null,score=Infinity;
    for(var i=0;i<candidates.length;i++){
      var el=candidates[i];if(el===current||!el.getClientRects().length)continue;
      var r=el.getBoundingClientRect(),dx=r.left+r.width/2-x,dy=r.top+r.height/2-y;
      var primary=direction==='ArrowRight'?dx:direction==='ArrowLeft'?-dx:direction==='ArrowDown'?dy:-dy;
      var cross=/Left|Right/.test(direction)?Math.abs(dy):Math.abs(dx);
      if(primary<=4)continue;
      var distance=primary+cross*3;if(distance<score){score=distance;best=el;}
    }
    if(best){e.preventDefault();best.focus();if(best.scrollIntoView)best.scrollIntoView({block:'nearest'});}
  });
  if(document.addEventListener){
    document.getElementById('larger-text').onclick=function(){
      var enabled=document.body.className.indexOf('large-text')<0;
      document.body.className=enabled?'console-page large-text':'console-page';
      this.setAttribute('aria-pressed',enabled?'true':'false');
    };
    document.getElementById('details-link').onclick=function(e){e.preventDefault();var settings=document.getElementById('session-details');settings.open=true;settings.querySelector('summary').focus();settings.scrollIntoView({block:'start'});};
    document.addEventListener('click',function(e){
      var el=e.target;while(el&&el.tagName!=='A')el=el.parentElement;
      if(active&&el&&(el.className==='suite-card'||el.id==='dashboard-link')){e.preventDefault();document.getElementById('session-note').textContent='Wait for this session to finish before switching pages.';}
    });
  }
  function show(text){log.textContent+=text+'\n';}
  function request(path,body,token){return new Promise(function(resolve,reject){var xhr=new XMLHttpRequest();xhr.open(body?'POST':'GET',path,true);xhr.timeout=5000;if(body)xhr.setRequestHeader('Content-Type','application/json');if(token)xhr.setRequestHeader('Authorization','Bearer '+token);xhr.onload=function(){if(xhr.status<200||xhr.status>=300)return reject(new Error('HTTP '+xhr.status+' '+xhr.responseText));try{resolve(JSON.parse(xhr.responseText));}catch(e){reject(e);}};xhr.onerror=function(){reject(new Error('Network request failed'));};xhr.ontimeout=function(){reject(new Error('Telemetry request timed out after 5 seconds'));};xhr.send(body?JSON.stringify(body):null);});}
  // Retry identical uncertain deliveries; collector deduplicates by sequence/hash.
  function postEvent(e){return request('api/event',e,run.token).catch(function(err){if(/^Error: HTTP (4|5)/.test(String(err)))throw err;return request('api/event',e,run.token);}).then(function(ack){if(ack.ok!==true||ack.seq!==e.seq||typeof ack.sha256!=='string')throw new Error('Invalid storage acknowledgment');e.server_ack=ack;return ack;});}
  function report(name,details,critical){queue=queue.then(function(){var e={run_id:run.run_id,seq:++seq,event:name,details:details||{},client_time:new Date().toISOString()};localEvents.push(e);return postEvent(e).then(function(ack){if(!critical)return ack;var confirmation={run_id:run.run_id,seq:++seq,event:'checkpoint_ack',details:{ack_seq:ack.seq},client_time:new Date().toISOString()};localEvents.push(confirmation);return postEvent(confirmation);});});return queue;}
  function bounded(test){return new Promise(function(resolve){var began=Date.now(),done=false,deadline=test.id==='http_repeats'?18000:3000,t=setTimeout(function(){finish({status:'TIMEOUT',observed:{message:'No asynchronous result within '+deadline+' ms'}});},deadline);function finish(result){if(done)return;done=true;clearTimeout(t);resolve({id:test.id,hypothesis:test.hypothesis,expected:test.expected,status:result.status||'PASS',observed:result.observed===undefined?result:result.observed,elapsed_ms:Math.max(0,Date.now()-began),suite_revision:run.suite_revision,timeout_ms:deadline,limitations:'Ordinary browser semantics only; synchronous hangs cannot be interrupted by this timeout.'});}Promise.resolve().then(function(){return test.run({request:request,source_sha256:run.version.source_sha256});}).then(finish,function(e){finish({status:'EXCEPTION',observed:{name:String(e.name||'Error'),message:String(e.message||e),stack:String(e.stack||'').slice(0,2048)}});});});}
  function executeTests(){var chain=Promise.resolve();tests.forEach(function(test){chain=chain.then(function(){progress('Testing '+readable(test.id)+'\u2026');return report('test_started',{id:test.id},true);}).then(function(){return bounded(test);}).then(function(result){completed++;if(result.status==='PASS')passed++;else if(result.status==='UNSUPPORTED'||result.status==='SKIPPED')unavailable++;else issues++;resultCard(result);progress(completed+' of '+tests.length+' tests returned');show(result.id+': '+result.status+' '+JSON.stringify(result.observed));return report('test_result',result,true);});});return chain;}
  start.onclick=function(){if(active)return;active=true;start.disabled=true;save.disabled=true;run=null;seq=0;queue=Promise.resolve();localEvents=[];log.textContent='';document.getElementById('results').textContent='';completed=0;passed=0;unavailable=0;issues=0;document.getElementById('results-panel').hidden=false;document.getElementById('results-link').hidden=false;document.getElementById('results-storage').textContent='Saving checkpoints\u2026';document.getElementById('session-note').hidden=false;document.getElementById('session-note').textContent='Keep this page open until the session finishes.';badge('RUNNING');progress('Starting your session\u2026');start.textContent='Test in progress\u2026';state.textContent='Starting\u2026';request('api/run',{origin_label:document.getElementById('origin').value,firmware:document.getElementById('firmware').value,model:document.getElementById('model').value,user_agent:navigator.userAgent,suite:suite}).then(function(meta){run=meta;if(JSON.stringify(meta.expected_test_ids)!==JSON.stringify(tests.map(function(t){return t.id;})))throw new Error('Frontend/collector suite mismatch; reload after server restart');document.getElementById('run').textContent='Run ID: '+run.run_id;state.textContent='Running '+suite+' tests';timer=setInterval(function(){if(active)report('heartbeat',{state:'running'},false).catch(function(){});},2000);return report('run_start',{random_seed:run.random_seed,parameters:run.parameters,suite:suite},true);}).then(executeTests).then(function(){clearInterval(timer);return report('run_completed',{note:'Browser suite returned; review individual results'},true);}).then(function(){state.textContent='Completed \u2014 '+totals()+'.';badge('SAVED');document.getElementById('results-storage').textContent='Saved to server';document.getElementById('session-note').textContent=unavailable?'Unavailable features are browser observations, not failed sessions.':'Session stored. View the results below or run another test.';progress('All results stored');},function(e){clearInterval(timer);state.textContent='Incomplete \u2014 the session could not finish.';badge('INCOMPLETE');document.getElementById('results-storage').textContent='Partial results; see log';document.getElementById('session-note').textContent='Check the technical log for the error. You can retry this test.';progress('Session incomplete \u00b7 last saved checkpoints retained');show(String(e));}).then(function(){active=false;start.disabled=false;start.textContent='Run again';save.disabled=!run;if(document.activeElement===document.body)start.focus();});};
  save.onclick=function(){var clean={run_id:run.run_id,origin_label:run.origin_label,version:run.version,events:localEvents};var blob=new Blob([JSON.stringify(clean,null,2)],{type:'application/json'}),url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download='browser-run-'+run.run_id+'.json';a.click();setTimeout(function(){URL.revokeObjectURL(url);},1000);};
  window.addEventListener('error',function(e){if(active&&run)report('javascript_error',{message:String(e.message),line:e.lineno,column:e.colno},false).catch(function(){});});
  window.addEventListener('unhandledrejection',function(e){if(active&&run)report('javascript_error',{message:String(e.reason)},false).catch(function(){});});
  window.addEventListener('pagehide',function(){if(active&&run)report('page_hidden',{note:'Best effort only; delivery not guaranteed'},false).catch(function(){});});
  request('api/config').then(function(){state.textContent='Ready to start. Results save automatically.';badge('READY');document.getElementById('connection-label').textContent='Collector online';document.getElementById('connection-label').className='connection-indicator connected';start.disabled=false;try{start.focus({preventScroll:true});}catch(e){start.focus();}},function(e){state.textContent='Collector unavailable. Reload the page to try again.';badge('OFFLINE');document.getElementById('connection-label').textContent='Collector offline';document.getElementById('connection-label').className='connection-indicator disconnected';show(String(e));});
})();
