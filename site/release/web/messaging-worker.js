/* Fixed valid clone/transfer exchange. No imports, storage or network calls. */
'use strict';
self.onmessage=function(e){
  var input=e.data;if(!input||input.probe!=='messaging-001'||(input.stage!=='clone'&&input.stage!=='transfer'))return;
  if(!(input.buffer instanceof ArrayBuffer)||input.buffer.byteLength!==32||!input.object||!input.object.nested)return;
  var bytes=new Uint8Array(input.buffer),matches=true;
  for(var i=0;i<32;i++)if(bytes[i]!==((i*7)&255))matches=false;
  bytes[0]=199;input.object.nested.value=99;
  var reply={probe:'messaging-001',stage:input.stage,received_bytes:32,input_pattern:matches,buffer:input.buffer,object:input.object};
  if(input.stage==='transfer')self.postMessage(reply,[input.buffer]);else self.postMessage(reply);
};
