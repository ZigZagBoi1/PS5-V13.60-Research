"""Bounded local browser diagnostics and append-only telemetry; Python stdlib only."""
import argparse
from collections import deque
from datetime import datetime, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import threading
import time
from urllib.parse import urlsplit
import uuid

ROOT = Path(__file__).resolve().parents[1]
MAX_BODY = 32768
RATE_LIMIT = 240
MAX_RELAPSE_LOG_LINES = 500
EVENTS = {'run_start', 'test_started', 'test_result', 'checkpoint_ack', 'heartbeat', 'javascript_error', 'run_completed', 'run_failed', 'page_hidden'}
TERMINAL = {'run_completed', 'run_failed'}
SUITES = {
    'messaging': {'experiment': 'browser-messaging', 'revision': 'messaging-001', 'test_ids': ['worker_messaging']},
    'context': {'experiment': 'browser-context', 'revision': 'context-001', 'test_ids': ['worker_context']},
    'baseline': {'experiment': 'browser-baseline', 'revision': 'baseline-002',
                 'test_ids': ['environment', 'api_presence', 'typedarray_dataview', 'bounded_allocation', 'exceptions', 'bigint', 'structured_clone', 'wasm_presence', 'network_health', 'timing']},
    'phase2': {'experiment': 'browser-phase2', 'revision': 'phase2-001',
               'test_ids': ['js_compatibility', 'buffer_views', 'wasm_diagnostics', 'microtask_order', 'error_propagation', 'clock_precision', 'http_repeats', 'webkit_api_matrix']},
    'ssvprobe': {'experiment': 'browser-ssvprobe', 'revision': 'ssvprobe-002',
                 'test_ids': ['ssv_history_basic', 'ssv_duplicate_ref', 'ssv_bigint_below_boundary', 'ssv_bigint_at_boundary', 'ssv_bigint_above_boundary', 'ssv_canary_after_probe']},
    'transformstream_feature': {'experiment': 'browser-transformstream-feature', 'revision': 'ts-feature-001',
                                'test_ids': ['transformstream_exposure']},
    'transformstream_regression': {'experiment': 'browser-transformstream-regression', 'revision': 'ts-regression-001',
                                   'test_ids': ['transformstream_plain_object']},
    'datalist_uaf_probe': {'experiment': 'webkit-datalist-lifetime', 'revision': 'datalist-lifetime-001',
                           'test_ids': ['datalist_button_type_change']},
}

def stamp():
    return datetime.now(timezone.utc).isoformat()

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode('utf-8')

def validate_event(value):
    if not isinstance(value, dict) or set(value) != {'run_id', 'seq', 'event', 'details', 'client_time'}:
        raise ValueError('Event fields do not match schema')
    if not isinstance(value['run_id'], str) or not re.fullmatch(r'[a-f0-9-]{36}', value['run_id']):
        raise ValueError('Invalid run ID')
    if type(value['seq']) is not int or not 1 <= value['seq'] <= 1000:
        raise ValueError('Invalid sequence')
    if not isinstance(value['event'], str) or value['event'] not in EVENTS:
        raise ValueError('Invalid event name')
    if not isinstance(value['details'], dict):
        raise ValueError('Details must be an object')
    if not isinstance(value['client_time'], str):
        raise ValueError('Invalid timestamp')
    dt = datetime.fromisoformat(value['client_time'].replace('Z', '+00:00'))
    if dt.tzinfo is None:
        raise ValueError('Timestamp must include timezone')
    canonical(value)  # Reject NaN/infinity and non-serializable input.
    if value['event'] == 'test_result':
        d = value['details']
        if not isinstance(d.get('id'), str) or len(d['id']) > 100 or d.get('status') not in {'PASS', 'FAIL', 'UNSUPPORTED', 'SKIPPED', 'UNEXPECTED_RESULT', 'EXCEPTION', 'TIMEOUT'}:
            raise ValueError('Invalid test result')
        if type(d.get('elapsed_ms')) not in (int, float) or not 0 <= d['elapsed_ms'] <= 60000:
            raise ValueError('Invalid duration')
    return value

def validate_relapse_diagnostics(value):
    if not isinstance(value, dict) or set(value) != {'session_id', 'firmware', 'lines'}:
        raise ValueError('Diagnostic fields do not match schema')
    session_id = value['session_id']
    try:
        if not isinstance(session_id, str) or str(uuid.UUID(session_id)) != session_id:
            raise ValueError('Invalid session ID')
    except (ValueError, AttributeError):
        raise ValueError('Invalid session ID')
    firmware = value['firmware']
    if not isinstance(firmware, str) or len(firmware) > 32 or not re.fullmatch(r'[0-9]+\.[0-9]{1,2}|unknown', firmware):
        raise ValueError('Invalid firmware label')
    lines = value['lines']
    if not isinstance(lines, list) or not 1 <= len(lines) <= 20:
        raise ValueError('Diagnostic batch must contain 1..20 lines')

    validated = []
    for line in lines:
        if not isinstance(line, dict) or set(line) != {'seq', 'level', 'message', 'client_time'}:
            raise ValueError('Diagnostic line fields do not match schema')
        seq = line['seq']
        if type(seq) is not int or not 1 <= seq <= MAX_RELAPSE_LOG_LINES:
            raise ValueError('Invalid diagnostic sequence')
        level = line['level']
        if level not in {'info', 'success', 'error', 'log'}:
            raise ValueError('Invalid diagnostic level')
        message = line['message']
        if not isinstance(message, str) or not message or len(message) > 800:
            raise ValueError('Invalid diagnostic message')
        message = re.sub(r'\b0x[0-9a-f]{6,16}\b', '0x[redacted]', message, flags=re.IGNORECASE)
        message = ''.join(ch for ch in message if ch in '\t' or ord(ch) >= 0x20)[:800]
        client_time = line['client_time']
        if not isinstance(client_time, str) or len(client_time) > 64:
            raise ValueError('Invalid client timestamp')
        dt = datetime.fromisoformat(client_time.replace('Z', '+00:00'))
        if dt.tzinfo is None:
            raise ValueError('Client timestamp must include timezone')
        validated.append({'seq': seq, 'level': level, 'message': message, 'client_time': client_time})

    if any(validated[i]['seq'] + 1 != validated[i + 1]['seq'] for i in range(len(validated) - 1)):
        raise ValueError('Diagnostic sequences must be consecutive')
    return session_id, firmware, validated

def source_version():
    files = {}
    for directory in ('server', 'web', 'experiments', 'dashboard'):
        for path in sorted((ROOT / directory).rglob('*')):
            if directory == 'web' and path.relative_to(ROOT / 'web').parts[0:1] == ('relapse',):
                # The pinned upstream release is tracked by its commit in
                # HV-INTEGRATION.md, not mixed into browser-test source hashes.
                continue
            if path.is_file() and path.suffix in ('.py', '.js', '.html', '.css', '.json') and '__pycache__' not in path.parts:
                files[path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return {'revision': 'diagnostics-007', 'source_sha256': hashlib.sha256(canonical(files)).hexdigest(), 'files': files, 'git_commit': None, 'git_note': 'Source hashes are authoritative; no project commit created.'}

def summarize(meta, events):
    end = next((e for e in reversed(events) if e['event'] in TERMINAL), None)
    last = events[-1] if events else None
    age = (datetime.now(timezone.utc) - datetime.fromisoformat(last['received_at_utc'] if last else meta['created_at_utc'])).total_seconds()
    confirmed = [e['details'].get('ack_seq') for e in events if e['event'] == 'checkpoint_ack']
    checkpoints = [e for e in events if e['event'] not in {'heartbeat', 'checkpoint_ack', 'page_hidden'}]
    terminal_details = end['details'] if end else None
    return dict(meta, outcome=('completed_browser_suite' if end and end['event'] == 'run_completed' else 'browser_reported_failure' if end else 'incomplete_unknown' if age > 15 else 'active_or_pending'),
                evidence_kind='browser_reported_observation', hardware_verified=False,
                last_stored_checkpoint=checkpoints[-1]['seq'] if checkpoints else None,
                last_client_confirmed_checkpoint=confirmed[-1] if confirmed else None,
                heartbeat_age_seconds=round(age, 2),
                server_duration_ms=round((datetime.fromisoformat(end['received_at_utc']) - datetime.fromisoformat(meta['created_at_utc'])).total_seconds() * 1000, 2) if end else None,
                results=[e['details'] for e in events if e['event'] == 'test_result'],
                terminal_event_details=terminal_details,
                probe_classification=terminal_details.get('classification') if meta.get('suite') == 'datalist_uaf_probe' and isinstance(terminal_details, dict) else None,
                probe_observation=terminal_details.get('raw_observation') if meta.get('suite') == 'datalist_uaf_probe' and isinstance(terminal_details, dict) else None,
                caveat='Missing telemetry does not distinguish navigation, connectivity loss, hang or crash. Browser tests do not demonstrate privileged execution.')

class Collector(ThreadingHTTPServer):
    daemon_threads = True
    def __init__(self, address, data_dir, rate_limit=RATE_LIMIT, public_origin=None, dashboard_key=None):
        self.data_dir = Path(data_dir)
        (self.data_dir / 'runs').mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self.tokens = {}
        self.rates = {}
        self.rate_limit = rate_limit
        self.public_origin = public_origin
        self.dashboard_key = dashboard_key
        self.storage_bytes = sum(p.stat().st_size for p in self.data_dir.rglob('*') if p.is_file())
        self.max_storage_bytes = 128 * 1024 * 1024
        self.relapse_diagnostics_dir = self.data_dir / 'relapse-diagnostics'
        self.relapse_diagnostics_dir.mkdir(parents=True, exist_ok=True)
        self.relapse_last_seq = {}
        self.relapse_digests = {}
        self.workers = threading.BoundedSemaphore(16)
        self.version = source_version()
        super().__init__(address, Handler)

    def process_request(self, request, client_address):
        if not self.workers.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.workers.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.workers.release()

    def get_request(self):
        sock, addr = super().get_request()
        sock.settimeout(8)
        return sock, addr

    def run_data(self, run_id):
        if not re.fullmatch(r'[a-f0-9-]{36}', run_id):
            raise ValueError('Invalid run ID')
        folder = self.data_dir / 'runs' / run_id
        meta = json.loads((folder / 'metadata.json').read_text(encoding='utf-8'))
        events = [json.loads(line) for line in (folder / 'events.jsonl').read_text(encoding='utf-8').splitlines() if line] if (folder / 'events.jsonl').exists() else []
        return meta, events

class Handler(BaseHTTPRequestHandler):
    server_version = 'PS5Research/0.2'
    def log_message(self, fmt, *args):
        # Do not print authorization tokens or query strings.
        print(stamp(), self.client_address[0], fmt % args)

    def route(self):
        path = urlsplit(self.path).path
        return path[4:] or '/' if path == '/ps5' or path.startswith('/ps5/') else path

    def send_bytes(self, status, data, mime, allow_same_origin_frame=False):
        self.send_response(status)
        frame_policy = "'self'" if allow_same_origin_frame else "'none'"
        x_frame_options = 'SAMEORIGIN' if allow_same_origin_frame else 'DENY'
        for key, value in {'Content-Type': mime, 'Content-Length': str(len(data)), 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'X-Frame-Options': x_frame_options, 'Content-Security-Policy': f"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' blob:; object-src 'none'; base-uri 'none'; frame-ancestors {frame_policy}"}.items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def respond(self, status, obj):
        if status >= 400 and self.command == 'POST' and not getattr(self, '_body_consumed', False):
            # Drain bounded rejected bodies before closing so Windows does not reset
            # the socket and discard the error response due to unread request data.
            try:
                length = int(self.headers.get('Content-Length', '0'))
                if 0 < length <= MAX_BODY * 2:
                    self.rfile.read(length)
            except (ValueError, OSError):
                pass
            self.close_connection = True
        self.send_bytes(status, canonical(obj), 'application/json; charset=utf-8')

    def origin_allowed(self):
        host = self.headers.get('Host', '')
        if self.server.public_origin:
            parsed = urlsplit(self.server.public_origin)
            if host == parsed.netloc and self.client_address[0] == '127.0.0.1':
                origin = self.headers.get('Origin')
                return not origin or origin == self.server.public_origin
        port = self.server.server_port
        allowed = {f'127.0.0.1:{port}', f'localhost:{port}', f'{self.server.server_address[0]}:{port}'}
        if host not in allowed:
            return False
        origin = self.headers.get('Origin')
        return not origin or origin == 'http://' + host

    def dashboard_allowed(self):
        if self.server.dashboard_key is None:
            return True
        return secrets.compare_digest(self.headers.get('X-Dashboard-Key', ''), self.server.dashboard_key)

    def client_ip(self):
        if self.server.public_origin and self.client_address[0] == '127.0.0.1':
            try:
                return str(ipaddress.ip_address(self.headers.get('X-Real-IP', '')))
            except ValueError:
                pass
        return self.client_address[0]

    def hv_client(self, require_origin=True):
        """Restrict HV requests to a LAN PS5 reporting firmware 13.60."""
        origin = self.headers.get('Origin')
        if (not self.server.public_origin or (origin and origin != self.server.public_origin)
                or (require_origin and origin != self.server.public_origin)):
            return None
        user_agent = self.headers.get('User-Agent', '')
        if not user_agent.startswith('Mozilla/5.0 (PlayStation; PlayStation 5/13.60)'):
            return None
        try:
            address = ipaddress.ip_address(self.client_ip())
        except ValueError:
            return None
        if address not in ipaddress.ip_network('10.0.0.0/24') or address == ipaddress.ip_address('10.0.0.80'):
            return None
        return str(address)

    def relapse_diagnostics_client(self):
        """Accept automatic Relapse logs only from a PS5 on the home LAN."""
        origin = self.headers.get('Origin')
        if self.server.public_origin and origin != self.server.public_origin:
            return None
        user_agent = self.headers.get('User-Agent', '')
        if not user_agent.startswith('Mozilla/5.0 (PlayStation; PlayStation 5/'):
            return None
        try:
            address = ipaddress.ip_address(self.client_ip())
        except ValueError:
            return None
        if address not in ipaddress.ip_network('10.0.0.0/24') or address == ipaddress.ip_address('10.0.0.80'):
            return None
        return str(address)

    def store_relapse_diagnostics(self, value):
        target = self.relapse_diagnostics_client()
        if not target:
            return self.respond(403, {'error': 'Relapse diagnostics are accepted only from a PS5 on the local network.'})
        session_id, firmware, lines = validate_relapse_diagnostics(value)
        path = self.server.relapse_diagnostics_dir / f'{session_id}.jsonl'

        with self.server.lock:
            last_seq = self.server.relapse_last_seq.get(session_id, 0)
            known = self.server.relapse_digests.setdefault(session_id, {})
            additions = []
            new_digests = {}
            for line in lines:
                normalized = dict(line, session_id=session_id, firmware=firmware)
                digest = hashlib.sha256(canonical(normalized)).hexdigest()
                if line['seq'] <= last_seq:
                    if known.get(line['seq']) != digest:
                        return self.respond(409, {'error': 'Diagnostic sequence was already stored with different content.'})
                    continue
                if line['seq'] != last_seq + 1:
                    return self.respond(409, {'error': 'Diagnostic sequence is out of order.'})
                entry = dict(normalized, received_at_utc=stamp())
                additions.append(canonical(entry) + b'\n')
                new_digests[line['seq']] = digest
                last_seq = line['seq']

            byte_count = sum(map(len, additions))
            if self.server.storage_bytes + byte_count > self.server.max_storage_bytes:
                return self.respond(507, {'error': 'Server diagnostics storage budget reached.'})
            if additions:
                with path.open('ab') as output:
                    for encoded in additions:
                        output.write(encoded)
                    output.flush()
                    os.fsync(output.fileno())
                self.server.storage_bytes += byte_count
                self.server.relapse_last_seq[session_id] = last_seq
                known.update(new_digests)

        return self.respond(200, {'ok': True, 'session_id': session_id, 'received': len(lines)})

    def hv_payload(self):
        return ROOT / 'private' / 'hv' / 'byepervisor_reborn.elf'

    def send_hv_payload(self, value):
        target = self.hv_client()
        if not target:
            return self.respond(403, {'error': 'The HV sender is available only from a PS5 on the local network.'})
        if not isinstance(value, dict) or set(value) != {'firmware', 'elfldr_ready'} or value.get('firmware') != '13.60' or value.get('elfldr_ready') is not True:
            return self.respond(400, {'error': 'Confirm the 13.60 firmware and that Relapse reports the ELF loader is listening on port 9021.'})

        payload_path = self.hv_payload()
        try:
            payload = payload_path.read_bytes()
        except OSError:
            return self.respond(503, {'error': 'The HV payload is not installed on the server.'})
        payload_sha256 = hashlib.sha256(payload).hexdigest()

        try:
            with socket.create_connection((target, 9021), timeout=5) as console:
                console.settimeout(10)
                console.sendall(payload)
                console.shutdown(socket.SHUT_WR)
        except OSError as exc:
            print(f'[HV] send failed target={target} code={type(exc).__name__}', flush=True)
            return self.respond(502, {'error': 'The ELF loader did not confirm a complete transfer. Read the console, then restart Relapse if needed. No retry was made.'})

        print(f'[HV] payload sent target={target} bytes={len(payload)} sha256={payload_sha256}', flush=True)
        return self.respond(200, {'sent': True, 'firmware': '13.60', 'target': target, 'port': 9021,
                                  'bytes_sent': len(payload), 'sha256': payload_sha256,
                                  'hv_confirmed': False,
                                  'message': 'The payload was sent to the ELF loader. Follow the Byepervisor instructions shown on the PS5; this does not confirm the HV bypass.'})

    def do_GET(self):
        if not self.origin_allowed():
            return self.respond(403, {'error': 'Host or origin rejected'})
        path = self.route()
        static = {'/': ('web/index.html', 'text/html'), '/index.html': ('web/index.html', 'text/html'), '/app.js': ('web/app.js', 'application/javascript'), '/ui.css': ('web/ui.css', 'text/css'), '/experiment.js': ('experiments/baseline.js', 'application/javascript'), '/dashboard': ('dashboard/index.html', 'text/html'), '/dashboard.js': ('dashboard/dashboard.js', 'application/javascript')}
        static['/phase2.js'] = ('experiments/phase2.js', 'application/javascript')
        static['/phase2'] = ('web/index.html', 'text/html')
        static['/context'] = ('web/index.html', 'text/html')
        static['/context.js'] = ('experiments/context.js', 'application/javascript')
        static['/context-worker.js'] = ('web/context-worker.js', 'application/javascript')
        static['/messaging'] = ('web/index.html', 'text/html')
        static['/messaging.js'] = ('experiments/messaging.js', 'application/javascript')
        static['/messaging-worker.js'] = ('web/messaging-worker.js', 'application/javascript')
        static['/ssvprobe'] = ('web/index.html', 'text/html')
        static['/ssvprobe.js'] = ('experiments/ssvprobe.js', 'application/javascript')
        static['/transformstream-feature'] = ('web/transformstream-feature.html', 'text/html')
        static['/transformstream-feature.js'] = ('web/transformstream-feature.js', 'application/javascript')
        static['/transformstream-regression'] = ('web/transformstream-regression.html', 'text/html')
        static['/transformstream-regression.js'] = ('web/transformstream-regression.js', 'application/javascript')
        static['/transformstream-regression-case'] = ('web/transformstream-regression-case.html', 'text/html')
        static['/transformstream-regression-case.js'] = ('web/transformstream-regression-case.js', 'application/javascript')
        static['/datalist-uaf-probe'] = ('web/datalist-uaf-probe.html', 'text/html')
        static['/datalist-uaf-probe.js'] = ('web/datalist-uaf-probe.js', 'application/javascript')
        static['/hv'] = ('web/hv.html', 'text/html')
        static['/hv.js'] = ('web/hv.js', 'application/javascript')
        static['/hv.css'] = ('web/hv.css', 'text/css')
        static['/hv-promo.css'] = ('web/hv-promo.css', 'text/css')
        static['/comparison.js'] = ('dashboard/comparison.js', 'application/javascript')
        if path in static:
            filename, mime = static[path]
            return self.send_bytes(200, (ROOT / filename).read_bytes(), mime + '; charset=utf-8', allow_same_origin_frame=path == '/transformstream-regression-case')
        if path in ('/health', '/api/health'):
            return self.respond(200, {'ok': True, 'server_utc': stamp(), 'version': self.server.version})
        if path == '/api/hv/status':
            target = self.hv_client(require_origin=False)
            if not target:
                return self.respond(403, {'error': 'The HV sender is available only from a PS5 on the local network.'})
            payload_path = self.hv_payload()
            try:
                payload = payload_path.read_bytes()
            except OSError:
                return self.respond(503, {'error': 'The HV payload is not installed on the server.'})
            return self.respond(200, {'eligible': True, 'firmware': '13.60', 'target': target,
                                      'payload_bytes': len(payload), 'sha256': hashlib.sha256(payload).hexdigest(),
                                      'loader_port': 9021, 'hv_confirmed': False})
        if path == '/api/config':
            return self.respond(200, {'experiment': 'browser-baseline', 'version': self.server.version, 'parameters': {'allocation_bytes': 1048576, 'timing_samples': 5, 'request_timeout_ms': 5000}})
        if path == '/api/runs':
            if not self.dashboard_allowed():
                return self.respond(401, {'error': 'Dashboard access key required'})
            with self.server.lock:
                folders = sorted((self.server.data_dir / 'runs').iterdir(), key=lambda p: p.stat().st_mtime, reverse=True)[:100]
                items = [summarize(*self.server.run_data(p.name)) for p in folders if p.is_dir()]
            return self.respond(200, {'runs': items})
        if path.startswith('/api/run/'):
            if not self.dashboard_allowed():
                return self.respond(401, {'error': 'Dashboard access key required'})
            try:
                with self.server.lock:
                    meta, events = self.server.run_data(path.rsplit('/', 1)[-1])
                return self.respond(200, {'summary': summarize(meta, events), 'events': events})
            except (ValueError, FileNotFoundError):
                return self.respond(404, {'error': 'Unknown run'})
        return self.respond(404, {'error': 'Not found'})

    def read_json(self):
        length = int(self.headers.get('Content-Length', '-1'))
        if not 0 < length <= MAX_BODY:
            raise OverflowError('Body must be 1..32768 bytes')
        self._body_consumed = True
        body = self.rfile.read(length)
        if len(body) != length:
            raise ValueError('Truncated body')
        if self.headers.get('Content-Encoding') or self.headers.get('Transfer-Encoding'):
            raise ValueError('Encoded or chunked bodies are not accepted')
        if self.headers.get('Content-Type', '').split(';')[0] != 'application/json':
            raise ValueError('Content-Type must be application/json')
        return json.loads(body.decode('utf-8'), parse_constant=lambda x: (_ for _ in ()).throw(ValueError('Nonfinite JSON')))

    def do_POST(self):
        if not self.origin_allowed():
            return self.respond(403, {'error': 'Host or origin rejected'})
        now = time.monotonic()
        with self.server.lock:
            self.server.rates = {ip: q for ip, q in self.server.rates.items() if q and now - q[-1] < 60}
            q = self.server.rates.setdefault(self.client_ip(), deque())
            while q and now - q[0] >= 60:
                q.popleft()
            limited = len(q) >= self.server.rate_limit
            if not limited:
                q.append(now)
        if limited:
            self.close_connection = True
            return self.respond(429, {'error': 'Request limit reached'})
        try:
            value = self.read_json()
            path = self.route()
            if path == '/api/hv/send':
                return self.send_hv_payload(value)
            if path == '/api/relapse/diagnostics':
                return self.store_relapse_diagnostics(value)
            if path == '/api/run':
                if not isinstance(value, dict) or set(value) not in ({'origin_label', 'firmware', 'model', 'user_agent'}, {'origin_label', 'firmware', 'model', 'user_agent', 'suite'}) or value['origin_label'] not in ('desktop_simulation', 'ps5_hardware_reported') or any(not isinstance(v, str) or len(v) > 1024 for v in value.values()):
                    raise ValueError('Invalid run metadata')
                suite = value.get('suite', 'baseline')
                if suite not in SUITES:
                    raise ValueError('Unknown diagnostic suite')
                run_id, token = str(uuid.uuid4()), secrets.token_urlsafe(32)
                meta = dict(value, run_id=run_id, created_at_utc=stamp(), version=self.server.version, metadata_verification='unverified_self_report', experiment='browser-baseline', random_seed=secrets.randbits(32), parameters={'allocation_bytes': 1048576, 'timing_samples': 5})
                meta.update(suite=suite, experiment=SUITES[suite]['experiment'],
                            suite_revision=SUITES[suite]['revision'], expected_test_ids=SUITES[suite]['test_ids'])
                if suite == 'phase2':
                    meta['parameters'] = {'buffer_bytes': 32, 'wasm_module_bytes': 8, 'clock_reads': 128, 'timer_samples': 5, 'health_requests': 3, 'test_timeout_ms': 3000, 'http_repeats_timeout_ms': 18000, 'request_timeout_ms': 5000}
                if suite == 'context':
                    meta['parameters'] = {'workers': 1, 'messages': 1, 'worker_deadline_ms': 2000, 'test_timeout_ms': 3000, 'compilation_attempts': 0}
                if suite == 'messaging':
                    meta['parameters'] = {'workers': 1, 'messages': 2, 'buffer_bytes': 32, 'worker_deadline_ms': 2000, 'test_timeout_ms': 3000, 'compilation_attempts': 0}
                if suite == 'ssvprobe':
                    meta['parameters'] = {'tests': 6, 'bigint_counts': [252, 254, 300], 'max_graph_elements': 302, 'test_timeout_ms': 3000, 'sequential': True, 'resource_exhaustion': False}
                if suite == 'transformstream_feature':
                    meta['parameters'] = {'checks': 1, 'constructor_calls': 0, 'iterator_mutations': 0}
                if suite == 'transformstream_regression':
                    meta['parameters'] = {'cases': 1, 'case': 'plain-object substitution', 'constructor_calls': 1,
                                          'iterator_overrides': 1, 'buffer_allocation_bytes': 0,
                                          'soft_deadline_ms': 5000, 'automatic_retry': False}
                if suite == 'datalist_uaf_probe':
                    meta['parameters'] = {'attempts': 1, 'max_click_wait_ms': 30000, 'resource_allocations': 'fixed DOM only',
                                          'forced_gc': False, 'heap_churn': False, 'automatic_retry': False,
                                          'security_conclusion_on_survival': 'none'}
                with self.server.lock:
                    if self.server.storage_bytes >= self.server.max_storage_bytes:
                        return self.respond(507, {'error': 'Collector storage budget reached; preserve/export existing data'})
                    if len(self.server.tokens) >= 1000:
                        return self.respond(429, {'error': 'Session run limit reached; preserve data and restart server'})
                    if source_version() != self.server.version:
                        return self.respond(409, {'error': 'Source changed on disk; restart server for a new version'})
                    folder = self.server.data_dir / 'runs' / run_id
                    folder.mkdir()
                    encoded_meta = canonical(meta)
                    (folder / 'metadata.json').write_bytes(encoded_meta)
                    self.server.storage_bytes += len(encoded_meta)
                    self.server.tokens[run_id] = token
                return self.respond(201, dict(meta, token=token))
            if path != '/api/event':
                return self.respond(404, {'error': 'Not found'})
            validate_event(value)
            run_id = value['run_id']
            token = self.headers.get('Authorization', '').removeprefix('Bearer ')
            with self.server.lock:
                expected = self.server.tokens.get(run_id)
                if not expected or not secrets.compare_digest(token, expected):
                    return self.respond(403, {'error': 'Unknown run or invalid token; start a new run after server restart'})
                meta, existing = self.server.run_data(run_id)
                if meta['version'] != source_version():
                    return self.respond(409, {'error': 'Source changed; start a new run'})
                digest = hashlib.sha256(canonical(value)).hexdigest()
                previous = next((e for e in existing if e['seq'] == value['seq']), None)
                if previous:
                    if previous['sha256'] != digest:
                        return self.respond(409, {'error': 'Sequence already stored with different content'})
                    return self.respond(200, {'ok': True, 'seq': previous['seq'], 'sha256': digest, 'duplicate': True})
                if value['seq'] != len(existing) + 1:
                    return self.respond(409, {'error': 'Sequence must be consecutive'})
                if any(e['event'] in TERMINAL for e in existing) and value['event'] not in ('checkpoint_ack', 'page_hidden'):
                    return self.respond(409, {'error': 'Run already ended'})
                if value['event'] == 'checkpoint_ack' and not any(e['seq'] == value['details'].get('ack_seq') for e in existing):
                    raise ValueError('Acknowledgment references missing checkpoint')
                item = dict(value, received_at_utc=stamp(), sha256=digest, schema_version=1)
                encoded = canonical(item) + b'\n'
                if self.server.storage_bytes + len(encoded) * 2 > self.server.max_storage_bytes:
                    return self.respond(507, {'error': 'Collector storage budget reached; preserve/export existing data'})
                with (self.server.data_dir / 'runs' / run_id / 'events.jsonl').open('ab') as output:
                    output.write(encoded)
                    output.flush()
                    os.fsync(output.fileno())
                with (self.server.data_dir / 'events.jsonl').open('ab') as output:
                    output.write(encoded)
                self.server.storage_bytes += len(encoded) * 2
            return self.respond(200, {'ok': True, 'seq': value['seq'], 'sha256': digest})
        except OverflowError as exc:
            self.close_connection = True
            return self.respond(413, {'error': str(exc)})
        except (ValueError, TypeError, UnicodeDecodeError, RecursionError) as exc:
            self.close_connection = True
            return self.respond(400, {'error': str(exc)})

def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', default='127.0.0.1', help='Loopback default; explicitly choose laptop LAN IPv4 for PS5 tests')
    parser.add_argument('--port', type=int, default=8765)
    parser.add_argument('--data-dir', type=Path, default=ROOT / 'data')
    parser.add_argument('--public-origin', help='Exact HTTPS origin, accepted only from the loopback reverse proxy')
    parser.add_argument('--dashboard-key-file', type=Path, help='Private file containing dashboard access key')
    args = parser.parse_args(argv)
    address = ipaddress.ip_address(args.host)
    if address.version != 4 or not (address.is_private or address.is_loopback) or address.is_unspecified:
        parser.error('Choose an explicit private/loopback IPv4, not a public or wildcard bind')
    if args.public_origin:
        parsed = urlsplit(args.public_origin)
        if args.host != '127.0.0.1' or parsed.scheme != 'https' or not parsed.netloc or parsed.path or parsed.query or parsed.fragment or not args.dashboard_key_file:
            parser.error('Public origin requires loopback binding, an exact HTTPS origin and a dashboard key file')
    return args

def main():
    args = arguments()
    key = args.dashboard_key_file.read_text(encoding='utf-8').strip() if args.dashboard_key_file else None
    if key is not None and len(key) < 32:
        raise ValueError('Dashboard access key must contain at least 32 characters')
    with Collector((args.host, args.port), args.data_dir, public_origin=args.public_origin, dashboard_key=key) as server:
        print(f'Browser research: http://{args.host}:{server.server_port}/ps5/', flush=True)
        print(f'Dashboard: http://{args.host}:{server.server_port}/ps5/dashboard', flush=True)
        print(f'Append-only data: {args.data_dir}', flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print('Stopped.')

if __name__ == '__main__':
    main()
