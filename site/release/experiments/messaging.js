/* One worker, two valid messages, one 32-byte buffer, total two-second deadline. */
(function(root){
  'use strict';
  var tests=[{id:'worker_messaging',hypothesis:'Ordinary worker messages clone data independently and transfer ArrayBuffer ownership',expected:'Clone preserves sender data; transfer detaches sender buffer and returns all 32 bytes',run:function(){
    if(typeof root.Worker!=='function')return {status:'UNSUPPORTED',observed:{stage:'constructor',message:'Worker unavailable'}};
    return new Promise(function(resolve){
      var worker=null,done=false,stage='constructor',buffer=new ArrayBuffer(32),view=new Uint8Array(buffer),object={nested:{value:7}},observed={buffer_bytes:32,messages:2};
      for(var i=0;i<32;i++)view[i]=(i*7)&255;
      var timer=setTimeout(function(){finish('TIMEOUT',{stage:stage,message:'No complete exchange within 2000 ms'});},2000);
      function finish(status,error){if(done)return;done=true;clearTimeout(timer);if(worker){worker.onmessage=null;worker.onerror=null;worker.terminate();}observed.worker_created=!!worker;observed.worker_terminated=!!worker;if(error)observed.error=error;resolve({status:status,observed:observed});}
      function bytesMatch(b){if(!(b instanceof ArrayBuffer)||b.byteLength!==32)return false;var bytes=new Uint8Array(b);if(bytes[0]!==199)return false;for(var j=1;j<32;j++)if(bytes[j]!==((j*7)&255))return false;return true;}
      try{
        worker=new root.Worker('messaging-worker.js');
        worker.onerror=function(e){if(e.preventDefault)e.preventDefault();finish('FAIL',{stage:stage,message:String(e.message||'Worker error')});};
        worker.onmessage=function(e){try{
          var reply=e.data;if(!reply||reply.probe!=='messaging-001'||reply.stage!==stage)throw new Error('Unexpected reply schema or stage');
          var check={worker_received_bytes:reply.received_bytes,worker_input_pattern:reply.input_pattern,returned_pattern:bytesMatch(reply.buffer),returned_object_value:reply.object&&reply.object.nested&&reply.object.nested.value};
          if(stage==='clone'){check.sender_bytes=buffer.byteLength;check.sender_first_byte=view[0];check.sender_object_value=object.nested.value;observed.clone=check;
            if(reply.received_bytes!==32||reply.input_pattern!==true||!check.returned_pattern||check.returned_object_value!==99||buffer.byteLength!==32||view[0]!==0||object.nested.value!==7)throw new Error('Clone assertions failed');
            stage='transfer';worker.postMessage({probe:'messaging-001',stage:stage,buffer:buffer,object:object},[buffer]);observed.sender_bytes_after_transfer=buffer.byteLength;
          }else{observed.transfer=check;if(reply.received_bytes!==32||reply.input_pattern!==true||!check.returned_pattern||check.returned_object_value!==99||observed.sender_bytes_after_transfer!==0)throw new Error('Transfer assertions failed');finish('PASS');}
        }catch(err){finish('FAIL',{stage:stage,name:String(err.name),message:String(err.message)});}};
        stage='clone';worker.postMessage({probe:'messaging-001',stage:stage,buffer:buffer,object:object});
      }catch(err){finish('FAIL',{stage:stage,name:String(err.name),message:String(err.message)});}
    });
  }}];
  root.ResearchSuites=root.ResearchSuites||{};root.ResearchSuites.messaging=tests;
  if(typeof module!=='undefined')module.exports=tests;
})(typeof window!=='undefined'?window:globalThis);
