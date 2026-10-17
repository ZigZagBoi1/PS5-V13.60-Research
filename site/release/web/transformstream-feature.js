(function () {
  'use strict';
  var state = document.getElementById('state');
  var start = document.getElementById('start');
  var download = document.getElementById('download');
  var output = document.getElementById('result');
  var ua = navigator.userAgent || '';
  var isPS5 = /PlayStation 5/.test(ua);
  var match = /PlayStation 5\/(\d+\.\d+)/.exec(ua);
  var events = [];
  var run = null;
  var seq = 0;
  var result = null;
  document.getElementById('origin').value = isPS5 ? 'ps5_hardware_reported' : 'desktop_simulation';
  document.getElementById('firmware').value = isPS5 && match ? match[1] : '';

  function request(path, body, token) {
    return new Promise(function (resolve, reject) {
      var xhr = new XMLHttpRequest();
      xhr.open(body ? 'POST' : 'GET', path, true);
      xhr.timeout = 5000;
      if (body) xhr.setRequestHeader('Content-Type', 'application/json');
      if (token) xhr.setRequestHeader('Authorization', 'Bearer ' + token);
      xhr.onload = function () {
        if (xhr.status < 200 || xhr.status >= 300) return reject(new Error('HTTP ' + xhr.status));
        try { resolve(JSON.parse(xhr.responseText)); } catch (e) { reject(e); }
      };
      xhr.onerror = function () { reject(new Error('Telemetry network failure')); };
      xhr.ontimeout = function () { reject(new Error('Telemetry request timed out')); };
      xhr.send(body ? JSON.stringify(body) : null);
    });
  }

  function send(name, details, critical) {
    var event = { run_id: run.run_id, seq: ++seq, event: name, details: details || {}, client_time: new Date().toISOString() };
    events.push(event);
    return request('api/event', event, run.token).then(function (ack) {
      event.server_ack = ack;
      if (!critical) return ack;
      var confirmation = { run_id: run.run_id, seq: ++seq, event: 'checkpoint_ack', details: { ack_seq: event.seq }, client_time: new Date().toISOString() };
      events.push(confirmation);
      return request('api/event', confirmation, run.token).then(function (confirmAck) {
        confirmation.server_ack = confirmAck;
        return confirmAck;
      });
    });
  }

  function observe() {
    var present = 'TransformStream' in globalThis;
    var valueType = typeof globalThis.TransformStream;
    return {
      property_present: present,
      value_type: valueType,
      is_function: valueType === 'function',
      is_secure_context: typeof isSecureContext === 'boolean' ? isSecureContext : null,
      user_agent: ua,
      check_scope: 'presence/type only; no constructor call or iterator mutation'
    };
  }

  function save() {
    var blob = new Blob([JSON.stringify({ run_id: run && run.run_id, version: run && run.version, suite_revision: run && run.suite_revision, result: result, events: events }, null, 2)], { type: 'application/json' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = 'transformstream-feature-' + ((run && run.run_id) || 'local') + '.json';
    a.click();
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }

  start.addEventListener('click', function () {
    start.disabled = true;
    state.textContent = 'Starting passive check…';
    request('api/run', {
      origin_label: document.getElementById('origin').value,
      firmware: document.getElementById('firmware').value,
      model: document.getElementById('model').value,
      user_agent: ua,
      suite: 'transformstream_feature'
    }).then(function (meta) {
      run = meta;
      if (meta.expected_test_ids.length !== 1 || meta.expected_test_ids[0] !== 'transformstream_exposure' || meta.suite_revision !== 'ts-feature-001') throw new Error('Unexpected collector suite version');
      return send('run_start', { scope: 'passive API exposure', suite_revision: meta.suite_revision, source_sha256: meta.version.source_sha256 }, true);
    }).then(function () {
      return send('test_started', { id: 'transformstream_exposure' }, true);
    }).then(function () {
      var began = Date.now();
      var observed = observe();
      result = {
        id: 'transformstream_exposure',
        status: observed.is_function ? 'PASS' : 'UNSUPPORTED',
        expected: 'Record exposure only; no security conclusion',
        observed: observed,
        elapsed_ms: Date.now() - began,
        suite_revision: run.suite_revision,
        test_source_sha256: run.version.files['web/transformstream-feature.js']
      };
      output.textContent = JSON.stringify(result, null, 2);
      download.disabled = false;
      return send('test_result', result, true);
    }).then(function () {
      return send('run_completed', { note: 'Passive feature exposure was recorded; this does not establish firmware correspondence or vulnerability.' }, true);
    }).then(function () {
      state.textContent = 'Observation stored. Review the raw result and provenance.';
    }).catch(function (error) {
      state.textContent = 'Run incomplete: ' + String(error.message || error);
      if (run) send('run_failed', { message: String(error.message || error), last_local_sequence: seq }, false).catch(function () {});
    }).then(function () {
      start.disabled = false;
    });
  });
  download.addEventListener('click', save);
  request('api/config').then(function () {
    state.textContent = 'Ready. This check only reads TransformStream property presence and type.';
    start.disabled = false;
  }, function (error) {
    state.textContent = 'Collector unavailable: ' + String(error.message || error);
  });
})();
