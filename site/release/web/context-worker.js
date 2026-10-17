/* Fixed capability snapshot only. No storage, imports, compilation or network calls. */
'use strict';
self.onmessage=function(e){
  if(!e.data||e.data.probe!=='context-001')return;
  var features={};['WebAssembly','indexedDB','Worker','SharedArrayBuffer','TextEncoder','fetch','performance'].forEach(function(name){features[name]={type:typeof self[name],present:name in self};});
  self.postMessage({probe:'context-001',snapshot:{features:features,secure_context:typeof self.isSecureContext==='boolean'?self.isSecureContext:null,user_agent:self.navigator.userAgent}});
};
