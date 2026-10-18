/* One ordinary same-origin worker, one message, two-second deadline. No compilation. */
(function(root){
  'use strict';
  function snapshot(target){var features={};['WebAssembly','indexedDB','Worker','SharedArrayBuffer','TextEncoder','fetch','performance'].forEach(function(name){features[name]={type:typeof target[name],present:name in target};});return {features:features,secure_context:typeof target.isSecureContext==='boolean'?target.isSecureContext:null,user_agent:target.navigator.userAgent};}
  var tests=[{id:'worker_context',hypothesis:'The same-origin worker context may expose a different API set from the page',expected:'One worker reply with API types and presence; both absence and presence are observations',run:function(){
    var page=snapshot(root);if(typeof root.Worker!=='function')return {status:'UNSUPPORTED',observed:{page:page,worker:'Worker constructor unavailable'}};
    return new Promise(function(resolve){var worker=null,done=false,timer=setTimeout(function(){finish('TIMEOUT',{stage:'message',message:'No worker reply within 2000 ms'});},2000);
      function finish(status,details){if(done)return;done=true;clearTimeout(timer);if(worker){worker.onmessage=null;worker.onerror=null;worker.terminate();}resolve({status:status,observed:{page:page,worker:details,worker_created:!!worker,worker_terminated:!!worker,limitation:'Ordinary worker execution stays inside the browser sandbox; API exposure does not identify build flags or privileges'}});}
      try{worker=new root.Worker('context-worker.js');worker.onmessage=function(e){if(!e.data||e.data.probe!=='context-001'||!e.data.snapshot)return finish('FAIL',{stage:'message',message:'Unexpected worker reply'});finish('PASS',e.data.snapshot);};worker.onerror=function(e){if(e.preventDefault)e.preventDefault();finish('FAIL',{stage:'worker_error',message:String(e.message||'Worker error')});};worker.postMessage({probe:'context-001'});}catch(e){finish('FAIL',{stage:'constructor',name:String(e.name),message:String(e.message)});}
    });
  }}];
  root.ResearchSuites=root.ResearchSuites||{};root.ResearchSuites.context=tests;
  if(typeof module!=='undefined')module.exports=tests;
})(typeof window!=='undefined'?window:globalThis);
