(function (root) {
  'use strict';

  var tests = [];

  function add(id, hypothesis, expected, run) {
    tests.push({ id: id, hypothesis: hypothesis, expected: expected, run: run });
  }

  function assert(ok, message) {
    if (!ok) throw new Error(message);
  }

  function unsupported(feature) {
    return { status: 'UNSUPPORTED', observed: feature + ' unavailable' };
  }

  add(
    'ssv_history_basic',
    'history.replaceState accepts and returns a simple object graph',
    'Roundtrip preserves structure',
    function () {
      if (typeof history === 'undefined' || typeof history.replaceState !== 'function')
        return unsupported('history.replaceState');

      var original = { a: 1, b: 'test', c: [10, 20, 30] };
      try {
        history.replaceState(original, '');
      } catch (e) {
        return { status: 'EXCEPTION', error: e.name + ': ' + e.message };
      }

      var restored;
      try {
        restored = history.state;
      } catch (e) {
        return { status: 'EXCEPTION', error: e.name + ': ' + e.message };
      }

      if (restored === null || restored === undefined)
        return { status: 'UNEXPECTED_RESULT', observed: 'state is ' + String(restored) };

      var ok = restored.a === 1 && restored.b === 'test' && restored.c && restored.c.length === 3 && restored.c[0] === 10 && restored.c[2] === 30;
      return {
        status: ok ? 'PASS' : 'UNEXPECTED_RESULT',
        a_match: restored.a === 1,
        b_match: restored.b === 'test',
        c_length: restored.c ? restored.c.length : -1,
        c_match: restored.c && restored.c[0] === 10 && restored.c[2] === 30
      };
    }
  );

  add(
    'ssv_duplicate_ref',
    'Structured clone preserves object identity for duplicate references',
    'result[0] and result[2] are the same object',
    function () {
      if (typeof history === 'undefined' || typeof history.replaceState !== 'function')
        return unsupported('history.replaceState');

      var marker = { id: 'DUPREF', value: 42 };
      var graph = [marker, 'separator', marker];

      try {
        history.replaceState(graph, '');
      } catch (e) {
        return { status: 'EXCEPTION', phase: 'replaceState', error: e.name + ': ' + e.message };
      }

      var result;
      try {
        result = history.state;
      } catch (e) {
        return { status: 'EXCEPTION', phase: 'state_access', error: e.name + ': ' + e.message };
      }

      if (!result || !Array.isArray(result))
        return { status: 'UNEXPECTED_RESULT', observed: 'state is ' + typeof result };

      var sameRef = result[0] === result[2];
      var valuesMatch = result[0] && result[2] && result[0].id === result[2].id;

      return {
        status: sameRef && valuesMatch && result.length === 3 ? 'PASS' : 'UNEXPECTED_RESULT',
        same_reference: sameRef,
        values_match: valuesMatch,
        first_id: result[0] ? result[0].id : null,
        third_id: result[2] ? result[2].id : null,
        first_value: result[0] ? result[0].value : null,
        third_value: result[2] ? result[2].value : null,
        length: result.length
      };
    }
  );

  add(
    'ssv_bigint_below_boundary',
    'Duplicate-reference roundtrip with a smaller BigInt graph',
    'Backreference resolves to the original marker and preserves its values',
    function () {
      if (typeof history === 'undefined' || typeof history.replaceState !== 'function')
        return unsupported('history.replaceState');
      if (typeof BigInt !== 'function')
        return unsupported('BigInt');

      var marker = { id: 'BELOW', sentinel: 0xBE };
      var graph = [marker];
      for (var i = 0; i < 252; i++) {
        graph.push(BigInt(i));
      }
      graph.push(marker);

      try {
        history.replaceState(graph, '');
      } catch (e) {
        return { status: 'EXCEPTION', phase: 'replaceState', error: e.name + ': ' + e.message };
      }

      var result;
      try {
        result = history.state;
      } catch (e) {
        return { status: 'EXCEPTION', phase: 'state_access', error: e.name + ': ' + e.message };
      }

      if (!result || !Array.isArray(result))
        return { status: 'UNEXPECTED_RESULT', observed: 'state is ' + typeof result };

      var lastIdx = result.length - 1;
      var first = result[0];
      var last = result[lastIdx];

      var ok = result.length === 254 && first === last && first && first.id === 'BELOW' && last.sentinel === 0xBE;
      return {
        status: ok ? 'PASS' : 'UNEXPECTED_RESULT',
        bigint_count: 252,
        array_length: result.length,
        same_reference: first === last,
        first_id: first ? first.id : null,
        last_id: last ? last.id : null,
        first_sentinel: first ? first.sentinel : null,
        last_sentinel: last ? last.sentinel : null,
        last_type: typeof last,
        last_is_object: typeof last === 'object' && last !== null
      };
    }
  );

  add(
    'ssv_bigint_at_boundary',
    'Duplicate-reference roundtrip with 254 BigInts near the probe hypothesized pool-size transition',
    'Backreference resolves to the original marker and preserves its values',
    function () {
      if (typeof history === 'undefined' || typeof history.replaceState !== 'function')
        return unsupported('history.replaceState');
      if (typeof BigInt !== 'function')
        return unsupported('BigInt');

      var marker = { id: 'BOUNDARY', sentinel: 0xBD };
      var graph = [marker];
      for (var i = 0; i < 254; i++) {
        graph.push(BigInt(i));
      }
      graph.push(marker);

      try {
        history.replaceState(graph, '');
      } catch (e) {
        return { status: 'EXCEPTION', phase: 'replaceState', error: e.name + ': ' + e.message };
      }

      var result = null;
      var stateError = null;
      try {
        result = history.state;
      } catch (e) {
        stateError = e.name + ': ' + e.message;
      }

      if (stateError)
        return {
          status: 'EXCEPTION',
          phase: 'state_access',
          error: stateError,
          bigint_count: 254,
          interpretation: 'History state access threw; this is a JavaScript exception, not proof of memory corruption'
        };

      if (result === null || result === undefined)
        return {
          status: 'UNEXPECTED_RESULT',
          bigint_count: 254,
          observed: 'state is ' + String(result),
          interpretation: 'Deserialization returned null; unexpected result, serialization or implementation defect remains possible'
        };

      if (!Array.isArray(result))
        return {
          status: 'UNEXPECTED_RESULT',
          bigint_count: 254,
          observed_type: typeof result,
          interpretation: 'Unexpected result type; no memory-corruption conclusion'
        };

      var lastIdx = result.length - 1;
      var first = result[0];
      var last = result[lastIdx];
      var sameRef = first === last;
      var firstOk = first && typeof first === 'object' && first.id === 'BOUNDARY';
      var lastOk = last && typeof last === 'object' && last.id === 'BOUNDARY';

      if (firstOk && lastOk && sameRef)
        return {
          status: 'PASS',
          bigint_count: 254,
          same_reference: true,
          interpretation: 'The specified graph and duplicate identity were preserved for this input'
        };

      return {
        status: 'UNEXPECTED_RESULT',
        bigint_count: 254,
        array_length: result.length,
        same_reference: sameRef,
        first_type: typeof first,
        last_type: typeof last,
        first_id: first && typeof first === 'object' ? first.id : String(first),
        last_id: last && typeof last === 'object' ? last.id : String(last),
        first_sentinel: first && typeof first === 'object' ? first.sentinel : null,
        last_sentinel: last && typeof last === 'object' ? last.sentinel : null,
        interpretation: 'Backreference did not preserve the specified graph; no memory-corruption conclusion'
      };
    }
  );

  add(
    'ssv_bigint_above_boundary',
    'Duplicate-reference roundtrip with a larger graph containing 300 BigInts',
    'Backreference resolves to the original marker and preserves its values',
    function () {
      if (typeof history === 'undefined' || typeof history.replaceState !== 'function')
        return unsupported('history.replaceState');
      if (typeof BigInt !== 'function')
        return unsupported('BigInt');

      var marker = { id: 'ABOVE', sentinel: 0xAB };
      var graph = [marker];
      for (var i = 0; i < 300; i++) {
        graph.push(BigInt(i));
      }
      graph.push(marker);

      try {
        history.replaceState(graph, '');
      } catch (e) {
        return { status: 'EXCEPTION', phase: 'replaceState', error: e.name + ': ' + e.message };
      }

      var result = null;
      var stateError = null;
      try {
        result = history.state;
      } catch (e) {
        stateError = e.name + ': ' + e.message;
      }

      if (stateError)
        return {
          status: 'EXCEPTION',
          phase: 'state_access',
          error: stateError,
          bigint_count: 300,
          interpretation: 'History state access threw; this is a JavaScript exception, not confirmation of a pool bug'
        };

      if (result === null || result === undefined)
        return {
          status: 'UNEXPECTED_RESULT',
          bigint_count: 300,
          observed: 'state is ' + String(result),
          interpretation: 'Deserialization returned null; unexpected result, no corruption conclusion'
        };

      if (!Array.isArray(result))
        return {
          status: 'UNEXPECTED_RESULT',
          bigint_count: 300,
          observed_type: typeof result,
          interpretation: 'Unexpected result type; no memory-corruption conclusion'
        };

      var lastIdx = result.length - 1;
      var first = result[0];
      var last = result[lastIdx];
      var sameRef = first === last;
      var firstOk = first && typeof first === 'object' && first.id === 'ABOVE';
      var lastOk = last && typeof last === 'object' && last.id === 'ABOVE';

      if (firstOk && lastOk && sameRef)
        return {
          status: 'PASS',
          bigint_count: 300,
          same_reference: true,
          interpretation: 'The specified graph and duplicate identity were preserved for this input'
        };

      return {
        status: 'UNEXPECTED_RESULT',
        bigint_count: 300,
        array_length: result.length,
        same_reference: sameRef,
        first_type: typeof first,
        last_type: typeof last,
        first_id: first && typeof first === 'object' ? first.id : String(first),
        last_id: last && typeof last === 'object' ? last.id : String(last),
        interpretation: 'Backreference did not preserve the specified graph; no memory-corruption conclusion'
      };
    }
  );

  add(
    'ssv_canary_after_probe',
    'Browser remains functional after pool boundary tests',
    'Basic structured clone still works',
    function () {
      if (typeof structuredClone !== 'function') return unsupported('structuredClone');
      var a = new Uint8Array([0xCA, 0xFE, 0xBA, 0xBE]);
      var b;
      try {
        b = structuredClone(a);
      } catch (e) {
        return { status: 'EXCEPTION', error: e.name + ': ' + e.message };
      }
      var ok = b && b.length === 4 && b[0] === 0xCA && b[1] === 0xFE && b[2] === 0xBA && b[3] === 0xBE;
      return {
        status: ok ? 'PASS' : 'UNEXPECTED_RESULT',
        clone_ok: b[0] === 0xCA && b[1] === 0xFE && b[2] === 0xBA && b[3] === 0xBE,
        browser_stable: true
      };
    }
  );

  root.ResearchSuites=root.ResearchSuites||{};root.ResearchSuites.ssvprobe=tests;
  if (typeof module !== 'undefined') module.exports = tests;
})(typeof window !== 'undefined' ? window : globalThis);
