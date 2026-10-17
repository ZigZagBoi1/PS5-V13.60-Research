(function () {
  'use strict';
  var state = document.getElementById('state');
  var start = document.getElementById('start');
  var visible = document.getElementById('visible');
  var notVisible = document.getElementById('not-visible');
  var download = document.getElementById('download');
  var output = document.getElementById('result');
  var runId = document.getElementById('run-id');
  var input = document.getElementById('choices-input');
  var list = document.getElementById('choices');
  var ua = navigator.userAgent || '';
  var isPS5 = /PlayStation 5/.test(ua);
  var match = /PlayStation 5\/(\d+\.\d+)/.exec(ua);
  var run = null;
  var sequence = 0;
  var events = [];
  var queue = Promise.resolve();
  var started = false;
  var armed = false;
  var finished = false;
  var armTime = 0;
  var clickTimer = null;
  var heartbeatTimer = null;
  var rawObservation = null;
  var failureReported = false;
  var exceptionPending = false;

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
    var event = { run_id: run.run_id, seq: ++sequence, event: name, details: details || {}, client_time: new Date().toISOString() };
    events.push(event);
    var operation = queue.then(function () { return request('api/event', event, run.token); }).then(function (ack) {
      event.server_ack = ack;
      if (!critical) return ack;
      var confirmation = { run_id: run.run_id, seq: ++sequence, event: 'checkpoint_ack', details: { ack_seq: event.seq }, client_time: new Date().toISOString() };
      events.push(confirmation);
      return request('api/event', confirmation, run.token).then(function (confirmAck) {
        confirmation.server_ack = confirmAck;
        return confirmAck;
      });
    });
    queue = operation;
    return operation;
  }

  function save() {
    var data = {
      run_id: run && run.run_id,
      version: run && run.version,
      suite_revision: run && run.suite_revision,
      classification: rawObservation && rawObservation.classification,
      raw_observation: rawObservation && rawObservation.raw_observation,
      events: events
    };
    var blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    var url = URL.createObjectURL(blob);
    var anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = 'datalist-lifetime-' + ((run && run.run_id) || 'local') + '.json';
    anchor.click();
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }

  function rawFeatureObservation() {
    return {
      html_datalist_interface_type: typeof window.HTMLDataListElement,
      input_list_property_present: 'list' in input,
      input_list_matches_page_element: input.list === list,
      native_control_visibility: 'operator_reported_after_visual_check'
    };
  }

  function reportFailure(error) {
    if (failureReported) return;
    failureReported = true;
    if (!finished) {
      finished = true;
      disarm();
    }
    var previous = rawObservation;
    rawObservation = {
      classification: 'telemetry_incomplete',
      raw_observation: { error: String(error && (error.message || error) || error), last_local_sequence: sequence,
        prior_observation: previous, events: events }
    };
    output.textContent = JSON.stringify(rawObservation, null, 2);
    download.disabled = false;
    state.textContent = 'Telemetry incomplete. Download the local raw observations if this page is still responsive; missing server data has no diagnosed cause.';
  }

  function disarm() {
    armed = false;
    if (clickTimer !== null) { clearTimeout(clickTimer); clickTimer = null; }
    if (heartbeatTimer !== null) { clearInterval(heartbeatTimer); heartbeatTimer = null; }
    input.removeEventListener('click', onInputClick, false);
    visible.disabled = true;
    notVisible.disabled = true;
  }

  function finish(classification, observation, terminalEvent) {
    if (finished || !run) return;
    finished = true;
    disarm();
    rawObservation = { classification: classification, raw_observation: observation };
    output.textContent = JSON.stringify(rawObservation, null, 2);
    download.disabled = false;
    send(terminalEvent || 'run_completed', {
      classification: classification,
      raw_observation: observation,
      security_conclusion: 'none; this browser observation cannot establish a vulnerability, firmware source identity, or exploitability'
    }, true).then(function () {
      state.textContent = 'Observation stored. This outcome has no jailbreak or vulnerability conclusion. Preserve the raw result and run ID.';
    }).catch(reportFailure);
  }

  function onInputClick(event) {
    if (!armed || finished) return;
    disarm();
    var rect = input.getBoundingClientRect();
    var localX = Number.isFinite(event.clientX) ? event.clientX - rect.left : null;
    var width = rect.width;
    var edgeStart = Math.max(0, width - 44);
    var qualifying = event.isTrusted === true && event.detail > 0 && localX !== null && localX >= edgeStart && localX <= width;
    var observation = {
      phase: 'operator_input_click',
      event_is_trusted: event.isTrusted === true,
      click_detail: Number(event.detail) || 0,
      client_x: Number.isFinite(event.clientX) ? event.clientX : null,
      input_left: rect.left,
      input_width: width,
      local_x: localX,
      accepted_right_edge_start: edgeStart,
      input_type_before: input.type,
      qualifying_click: qualifying,
      elapsed_since_arm_ms: Math.max(0, Math.round(performance.now() - armTime))
    };

    if (!qualifying) {
      observation.input_type_after = input.type;
      return finish('not_run_unqualified_click', observation);
    }

    observation.type_change_requested = true;
    try {
      input.type = 'button';
    } catch (error) {
      observation.type_change_exception = { name: String(error && error.name || 'Error'), message: String(error && error.message || error) };
      send('javascript_error', { id: 'datalist_button_type_change', error: observation.type_change_exception, raw_observation: observation }, false)
        .then(function () { finish('javascript_exception_during_type_change', observation); })
        .catch(reportFailure);
      return;
    }

    // Let the trusted click dispatch, including the browser's default handling,
    // return before performing telemetry work or reading the changed input.
    setTimeout(function () {
      try {
        observation.input_type_after = input.type;
        observation.callback_returned = true;
        observation.page_survived_dispatch = true;
        finish('input_type_changed_no_crash_observed', observation);
      } catch (error) {
        observation.post_dispatch_exception = { name: String(error && error.name || 'Error'), message: String(error && error.message || error) };
        send('javascript_error', { id: 'datalist_button_type_change', phase: 'after_click_dispatch', error: observation.post_dispatch_exception, raw_observation: observation }, false)
          .then(function () { finish('javascript_exception_after_click_dispatch', observation); })
          .catch(reportFailure);
      }
    }, 0);
  }

  window.addEventListener('error', function (event) {
    if (!run || finished || exceptionPending) return;
    exceptionPending = true;
    disarm();
    var error = event && event.error;
    var observation = {
      phase: 'uncaught_page_javascript_exception',
      message: String(event && event.message || ''),
      filename: String(event && event.filename || ''),
      line: Number(event && event.lineno) || 0,
      column: Number(event && event.colno) || 0,
      error_name: String(error && error.name || ''),
      error_message: String(error && error.message || '')
    };
    send('javascript_error', { id: 'datalist_button_type_change', raw_observation: observation }, false)
      .then(function () { finish('javascript_exception_uncaught', observation); })
      .catch(reportFailure);
  });

  function arm() {
    if (finished || armed) return;
    var feature = rawFeatureObservation();
    visible.disabled = true;
    notVisible.disabled = true;
    state.textContent = 'Saving the one-shot arming checkpoint…';
    send('test_started', {
      id: 'datalist_button_type_change',
      phase: 'armed_for_one_manual_click',
      execution_confirmed: false,
      max_click_wait_ms: 30000,
      page_feature_observation: feature
    }, true).then(function () {
      armed = true;
      armTime = performance.now();
      input.addEventListener('click', onInputClick, false);
      state.textContent = 'Armed for one trusted click on the visible right-side datalist control. A click elsewhere will be recorded without changing the input. No retry.';
      clickTimer = setTimeout(function () {
        finish('not_run_no_qualifying_click_within_30s', {
          phase: 'armed_wait_expired',
          elapsed_ms: Math.max(0, Math.round(performance.now() - armTime)),
          click_received: false,
          input_type: input.type,
          max_click_wait_ms: 30000
        });
      }, 30000);
      heartbeatTimer = setInterval(function () {
        if (!finished) send('heartbeat', { state: 'armed_waiting_for_one_manual_click' }, false).catch(function () {});
      }, 5000);
    }).catch(reportFailure);
  }

  start.addEventListener('click', function () {
    if (started) return;
    started = true;
    start.disabled = true;
    state.textContent = 'Starting one-shot run…';
    request('api/run', {
      origin_label: document.getElementById('origin').value,
      firmware: document.getElementById('firmware').value,
      model: document.getElementById('model').value,
      user_agent: ua,
      suite: 'datalist_uaf_probe'
    }).then(function (meta) {
      run = meta;
      if (meta.expected_test_ids.length !== 1 || meta.expected_test_ids[0] !== 'datalist_button_type_change' || meta.suite_revision !== 'datalist-lifetime-001') throw new Error('Unexpected collector suite version');
      runId.textContent = 'Run ID: ' + run.run_id;
      return send('run_start', {
        scope: 'one manual datalist-control click followed by one input type change',
        suite_revision: meta.suite_revision,
        source_sha256: meta.version.source_sha256,
        test_source_sha256: meta.version.files['web/datalist-uaf-probe.js'],
        page_feature_observation: rawFeatureObservation(),
        automatic_click: false,
        forced_gc: false,
        heap_churn: false,
        automatic_retry: false
      }, true);
    }).then(function () {
      visible.hidden = false;
      notVisible.hidden = false;
      visible.disabled = false;
      notVisible.disabled = false;
      state.textContent = 'Run created and first checkpoint saved. Confirm whether the browser visibly shows its own datalist control.';
    }).catch(reportFailure);
  });

  visible.addEventListener('click', arm);
  notVisible.addEventListener('click', function () {
    finish('not_run_control_not_visible', {
      phase: 'operator_visual_check',
      native_control_visible: false,
      page_feature_observation: rawFeatureObservation(),
      click_attempted: false
    });
  });
  download.addEventListener('click', save);

  request('api/config').then(function () {
    state.textContent = 'Ready. No test runs until you start it; no input action is synthetic.';
    start.disabled = false;
  }, function (error) {
    state.textContent = 'Collector unavailable: ' + String(error.message || error);
  });
})();
