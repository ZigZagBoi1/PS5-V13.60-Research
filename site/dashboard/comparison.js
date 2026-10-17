/* Comparison groups retain source, suite and browser provenance. */
(function(root){
  'use strict';
  function compare(runs){
    var groups={},warnings=[];
    runs.forEach(function(r){
      var browser=/PlayStation 5/.test(r.user_agent||'')?'PS5 UA hint':'desktop/other UA hint';
      if(browser==='PS5 UA hint'&&r.origin_label==='desktop_simulation')warnings.push(r.run_id+': PS5 UA hint conflicts with original desktop label; operator correlation required.');
      if(r.outcome!=='completed_browser_suite')warnings.push(r.run_id+': '+r.outcome+'; missing telemetry has no diagnosed cause.');
      r.results.forEach(function(t){
        var suite=r.suite_revision||r.version.revision,k=JSON.stringify([suite,r.version.source_sha256,r.user_agent||'',t.id]);
        var g=groups[k]||(groups[k]={suite:suite,source:r.version.source_sha256,browser:browser,user_agent:r.user_agent||'',test:t.id,runs:[],statuses:{},observations:{},durations:[]});
        g.runs.push(r.run_id);g.statuses[t.status]=true;g.observations[JSON.stringify(t.observed)]=true;g.durations.push(t.elapsed_ms);
        if(t.status==='FAIL'||t.status==='UNEXPECTED_RESULT'||t.status==='EXCEPTION'||t.status==='TIMEOUT')warnings.push(r.run_id+' '+t.id+': '+t.status+' requires investigation; no security impact inferred.');
        if((t.id==='wasm_presence'||t.id==='wasm_diagnostics')&&t.status==='UNSUPPORTED')warnings.push(r.run_id+': WebAssembly limitation observed; build configuration and cause unknown.');
      });
    });
    return {groups:Object.keys(groups).map(function(k){var g=groups[k];g.statuses=Object.keys(g.statuses);g.observation_variants=Object.keys(g.observations).length;delete g.observations;g.min_ms=Math.min.apply(null,g.durations);g.max_ms=Math.max.apply(null,g.durations);if(g.statuses.length>1)warnings.push(g.test+': outcome differs across matching source/browser trials.');return g;}),warnings:warnings};
  }
  root.compareResearchRuns=compare;if(typeof module!=='undefined')module.exports=compare;
})(typeof window!=='undefined'?window:globalThis);
