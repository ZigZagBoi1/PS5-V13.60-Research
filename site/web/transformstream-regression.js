(function () {
  'use strict';
  var state = document.getElementById('state');
  var start = document.getElementById('start');
  var download = document.getElementById('download');
  var output = document.getElementById('result');
  var frame = document.getElementById('case-frame');
  var ua = navigator.userAgent || '';
  var isPS5 = /PlayStation 5/.test(ua);
  var match = /PlayStation 5\/(\d+\.\d+)/.exec(ua);
  var events = [];
  var run = null;
  var seq = 0;
  var result = null;
  var started = false;
  var timeoutId = null;
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
        try { resolve(JSON.parse(xhr.responseText)); } catch (error) { reject(error); }
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

  function save() {
    var blob = new Blob([JSON.stringify({ run_id: run && run.run_id, version: run && run.version, suite_revision: run && run.suite_revision, result: result, events: events }, null, 2)], { type: 'application/json' });
    var url = URL.createObjectURL(blob);
    var anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = 'transformstream-regression-' + ((run && run.run_id) || 'local') + '.json';
    anchor.click();
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }

  function finish(observation, status, isTimeout) {
    if (!run || result) return;
    if (timeoutId) clearTimeout(timeoutId);
    frame.removeAttribute('src');
    frame.hidden = true;
    result = {
      id: 'transformstream_plain_object',
      status: status,
      expected: 'A TypeError is the expected safe rejection in the fixed upstream implementation; it does not prove this browser is patched.',
      observed: observation,
      elapsed_ms: observation && typeof observation.elapsed_ms === 'number' ? observation.elapsed_ms : 5000,
      suite_revision: run.suite_revision,
      test_source_sha256: run.version.files['web/transformstream-regression-case.js']
    };
    output.textContent = JSON.stringify(result, null, 2);
    download.disabled = false;
    var eventChain = send('test_result', result, true);
    if (isTimeout) {
      eventChain.then(function () {
        return send('run_failed', { reason: 'No child-frame result by the soft deadline; whether the case executed is unknown.' }, false);
      }).then(function () {
        state.textContent = 'No frame result arrived by the soft deadline; whether the case executed is unknown. Do not retry if the browser hung or restarted.';
      }).catch(reportFailure);
      return;
    }
    eventChain.then(function () {
      return send('run_completed', { note: 'One manual plain-object regression case completed. This result is not proof of firmware source identity or exploitability.' }, true);
    }).then(function () {
      state.textContent = 'One case completed and stored. Preserve the raw result and run ID.';
    }).catch(reportFailure);
  }

  function reportFailure(error) {
    state.textContent = 'Telemetry incomplete: ' + String(error.message || error);
    if (run) send('run_failed', { message: String(error.message || error), last_local_sequence: seq }, false).catch(function () {});
  }

  window.addEventListener('message', function (event) {
    if (!frame.contentWindow || event.source !== frame.contentWindow || !event.data || event.data.type !== 'transformstream-case-result') return;
    var message = event.data;
    if (message.outcome === 'type_error') return finish(message.observed, 'PASS', false);
    if (message.outcome === 'unsupported') return finish(message.observed, 'UNSUPPORTED', false);
    if (message.outcome === 'no_exception') return finish(message.observed, 'UNEXPECTED_RESULT', false);
    return finish(message.observed, 'EXCEPTION', false);
  });

  start.addEventListener('click', function () {
    if (started) return;
    started = true;
    start.disabled = true;
    state.textContent = 'Starting one manual regression case…';
    request('api/run', {
      origin_label: document.getElementById('origin').value,
      firmware: document.getElementById('firmware').value,
      model: document.getElementById('model').value,
      user_agent: ua,
      suite: 'transformstream_regression'
    }).then(function (meta) {
      run = meta;
      if (meta.expected_test_ids.length !== 1 || meta.expected_test_ids[0] !== 'transformstream_plain_object' || meta.suite_revision !== 'ts-regression-001') throw new Error('Unexpected collector suite version');
      return send('run_start', { scope: 'one plain-object substitution; manual click; no auto-repeat', suite_revision: meta.suite_revision, source_sha256: meta.version.source_sha256 }, true);
    }).then(function () {
      return send('test_started', { id: 'transformstream_plain_object', case_dispatch_attempted: true, execution_confirmed: false, soft_deadline_ms: 5000 }, true);
    }).then(function () {
      state.textContent = 'Running one case. If the browser closes or restarts, do not run it again.';
      timeoutId = setTimeout(function () {
        finish({ case: 'single plain-object substitution', constructor_calls: null, iterator_override_attempted: null, iterator_restored: null, child_execution_state: 'unknown', timeout_ms: 5000, result_received: false }, 'TIMEOUT', true);
      }, 5000);
      frame.src = 'transformstream-regression-case';
    }).catch(reportFailure);
  });
  download.addEventListener('click', save);

  request('api/config').then(function () {
    state.textContent = 'Ready. One click runs one bounded case; no automatic retry.';
    start.disabled = false;
  }, function (error) {
    state.textContent = 'Collector unavailable: ' + String(error.message || error);
  });
})();
