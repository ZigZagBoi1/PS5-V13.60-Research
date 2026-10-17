(function () {
  'use strict';
  var started = performance.now();
  var originalIterator = Array.prototype[Symbol.iterator];
  var observation = {
    property_present: 'TransformStream' in globalThis,
    value_type: typeof globalThis.TransformStream,
    is_secure_context: typeof isSecureContext === 'boolean' ? isSecureContext : null,
    case: 'single plain-object substitution',
    constructor_calls: 0,
    iterator_override_attempted: false,
    iterator_restored: false,
    error_name: null,
    error_message: null,
    elapsed_ms: null
  };

  if (observation.value_type !== 'function' || !observation.is_secure_context) {
    observation.elapsed_ms = Math.round(performance.now() - started);
    parent.postMessage({ type: 'transformstream-case-result', outcome: 'unsupported', observed: observation }, location.origin);
    return;
  }

  observation.iterator_override_attempted = true;
  Array.prototype[Symbol.iterator] = function () {
    var array = this;
    var index = 0;
    return {
      next: function () {
        if (index >= array.length) return { done: true };
        var value = array[index];
        if (array.length === 3 && index >= 1) value = { fake: true };
        index++;
        return { value: value, done: false };
      }
    };
  };

  try {
    observation.constructor_calls = 1;
    new globalThis.TransformStream();
    observation.error_name = 'NoException';
    observation.error_message = 'TransformStream construction returned without throwing';
  } catch (error) {
    observation.error_name = error && error.name ? String(error.name) : 'NonErrorThrown';
    observation.error_message = String(error && error.message ? error.message : error).slice(0, 300);
  } finally {
    Array.prototype[Symbol.iterator] = originalIterator;
    observation.iterator_restored = Array.prototype[Symbol.iterator] === originalIterator;
    observation.elapsed_ms = Math.round(performance.now() - started);
  }

  var outcome = observation.error_name === 'TypeError' ? 'type_error' :
    observation.error_name === 'NoException' ? 'no_exception' : 'exception';
  parent.postMessage({ type: 'transformstream-case-result', outcome: outcome, observed: observation }, location.origin);
})();
