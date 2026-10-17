/* phase2-001: ordinary semantics, fixed inputs, no eval or engine stress. */
(function (root) {
  'use strict';
  var tests=[];
  function add(id,hypothesis,expected,run){tests.push({id:id,hypothesis:hypothesis,expected:expected,run:run});}
  function assert(ok,message){if(!ok)throw new Error(message);}
  function error(e){return {name:String(e.name||'Error'),message:String(e.message||e)};}
  function absent(api){return {status:'UNSUPPORTED',observed:{unavailable:api}};}
  function now(){return root.performance&&typeof root.performance.now==='function'?root.performance.now():Date.now();}
  add('js_compatibility','Standard language library operations preserve their documented values','Descriptor, bind and JSON round-trip; optional methods measured',function(){
    var o={};Object.defineProperty(o,'value',{value:7,enumerable:true});
    assert(o.value===7&&JSON.parse(JSON.stringify(o)).value===7,'Descriptor/JSON mismatch');
    assert(function(x){return this.value+x;}.bind(o)(2)===9,'bind mismatch');
    var features={array_includes:typeof Array.prototype.includes==='function',array_find:typeof Array.prototype.find==='function',object_assign:typeof Object.assign==='function',number_isSafeInteger:typeof Number.isSafeInteger==='function',map:typeof Map==='function',set:typeof Set==='function',symbol:typeof Symbol==='function'};
    if(features.array_includes)assert([1,2].includes(2),'includes mismatch');
    if(features.array_find)assert([1,2].find(function(v){return v===2;})===2,'find mismatch');
    return {features:features,descriptor_json_bind:true,syntax_probe:'ES5-compatible source; newer syntax not measured'};
  });
  add('buffer_views','Valid aliases, copies and endian reads have ordinary semantics','Aliased byte 9, copied byte 2; invalid DataView read throws RangeError',function(){
    if(typeof ArrayBuffer!=='function'||typeof DataView!=='function'||typeof Uint8Array!=='function')return absent('buffer APIs');
    var b=new ArrayBuffer(32),a=new Uint8Array(b),v=new DataView(b);a.set([1,2,3,4]);
    var alias=a.subarray(1,3),copy=b.slice(1,3);alias[0]=9;
    assert(a[1]===9&&new Uint8Array(copy)[0]===2,'View/copy mismatch');
    v.setUint16(8,0x1234,false);assert(a[8]===0x12&&v.getUint16(8,true)===0x3412,'Endian mismatch');
    var range=false;try{v.getUint32(31);}catch(e){range=e.name==='RangeError';}assert(range,'Expected range exception');
    return {bytes:32,aliased_byte:a[1],copied_byte:new Uint8Array(copy)[0],range_error:range};
  });
  add('wasm_diagnostics','Property inspection separates absence from compilation failure','API shape plus validation and instantiation of an 8-byte empty module',function(){
    var out={identifier_type:typeof WebAssembly,property_present:'WebAssembly' in root,own_property:Object.prototype.hasOwnProperty.call(root,'WebAssembly'),secure_context:typeof root.isSecureContext==='boolean'?root.isSecureContext:null,execution_tested:false};
    var w;try{w=root.WebAssembly;out.property_type=typeof w;out.null_value=w===null;var d=Object.getOwnPropertyDescriptor(root,'WebAssembly');out.descriptor=d?{configurable:d.configurable,enumerable:d.enumerable,getter:typeof d.get==='function'}:null;}catch(e){out.stage='property_access';out.exception=error(e);return {status:'FAIL',observed:out};}
    if(!w){out.classification='API not exposed in this page context; cause unknown';return {status:'UNSUPPORTED',observed:out};}
    out.methods={validate:typeof w.validate,Module:typeof w.Module,Instance:typeof w.Instance,compile:typeof w.compile,instantiate:typeof w.instantiate};
    if(typeof w.validate!=='function'||typeof w.Module!=='function'||typeof w.Instance!=='function'){out.classification='API exposed with incomplete method set';return {status:'UNSUPPORTED',observed:out};}
    try{out.stage='validate';var bytes=new Uint8Array([0,97,115,109,1,0,0,0]);out.valid=w.validate(bytes);assert(out.valid,'Valid empty module rejected');out.stage='compile';var m=new w.Module(bytes);out.stage='instantiate';var instance=new w.Instance(m);out.exports=Object.keys(instance.exports);out.module_bytes=bytes.length;out.execution_tested=true;out.execution_scope='Empty module instantiation; no function body executed';out.classification='Empty module accepted';return out;}catch(e){out.exception=error(e);out.classification='API exposed but operation failed; exception is evidence, not a root cause';return {status:'FAIL',observed:out};}
  });
  add('microtask_order','Promise reactions complete before the next timer task','sync, promise, nested, timer',function(){
    if(typeof Promise!=='function')return absent('Promise');
    var order=['sync'];return new Promise(function(resolve,reject){Promise.resolve().then(function(){order.push('promise');Promise.resolve().then(function(){order.push('nested');});});setTimeout(function(){try{order.push('timer');assert(order.join(',')==='sync,promise,nested,timer','Unexpected task order');resolve({order:order,queueMicrotask:typeof root.queueMicrotask==='function'});}catch(e){reject(e);}},0);});
  });
  add('error_propagation','A handled Promise rejection preserves error identity','TypeError reaches catch once, chain recovers to 11',function(){
    var original=new TypeError('phase2-controlled-error'),caught=0;
    return Promise.resolve().then(function(){throw original;}).catch(function(e){assert(e===original,'Error identity changed');caught++;return 11;}).then(function(v){assert(v===11&&caught===1,'Recovery mismatch');return {name:original.name,message:original.message,catches:caught,recovered:v};});
  });
  add('clock_precision','Bounded samples record clock increments without assuming precision','128 clock reads and five zero-delay timer samples',function(){
    var values=[],deltas=[],backward=0,i;for(i=0;i<128;i++)values.push(now());
    for(i=1;i<values.length;i++){var d=values[i]-values[i-1];if(d<0)backward++;if(d>0)deltas.push(d);}
    var timers=[];return new Promise(function(resolve){function sample(){var start=now();setTimeout(function(){timers.push(now()-start);if(timers.length<5)sample();else resolve({clock:root.performance&&typeof root.performance.now==='function'?'performance.now':'Date.now',reads:128,positive_steps:deltas.length,min_positive_step_ms:deltas.length?Math.min.apply(null,deltas):null,backward_steps:backward,requested_delay_ms:0,timer_samples_ms:timers,limitation:'Observed resolution only; scheduling and page context affect samples'});},0);}sample();});
  });
  add('http_repeats','Three sequential same-origin requests identify stable server provenance','Three ok responses with the current run source hash',function(ctx){
    var samples=[],chain=Promise.resolve();for(var i=0;i<3;i++)chain=chain.then(function(){var start=now();return ctx.request('health').then(function(r){assert(r.ok===true,'Health rejected');assert(r.version.source_sha256===ctx.source_sha256,'Server source changed');samples.push({elapsed_ms:now()-start,source_sha256:r.version.source_sha256,server_utc:r.server_utc});});});
    return chain.then(function(){return {requests:3,samples:samples,transport:'XMLHttpRequest',scope:'Health reads plus separate acknowledged test checkpoints; no packet loss rate inferred'};});
  });
  add('webkit_api_matrix','Standard and prefixed APIs can be measured without privileged calls','Presence matrix and CSS support booleans; engine version remains unknown',function(){
    var names=['webkitRequestAnimationFrame','requestAnimationFrame','webkitIndexedDB','indexedDB','webkitAudioContext','AudioContext','WebKitMutationObserver','MutationObserver','Worker','fetch','TextEncoder','structuredClone','SharedArrayBuffer'],features={};
    names.forEach(function(name){try{features[name]=typeof root[name];}catch(e){features[name]='access_error:'+e.name;}});
    var css={};if(root.CSS&&typeof root.CSS.supports==='function'){['display: grid','display: flex','-webkit-appearance: none'].forEach(function(v){css[v]=root.CSS.supports(v);});}
    return {features:features,css_supports:css,cross_origin_isolated:typeof root.crossOriginIsolated==='boolean'?root.crossOriginIsolated:null,limitation:'Presence and prefix names do not identify the shipped WebKit/JSC revision'};
  });
  root.ResearchSuites=root.ResearchSuites||{};root.ResearchSuites.phase2=tests;
  if(typeof module!=='undefined')module.exports=tests;
})(typeof window!=='undefined'?window:globalThis);
