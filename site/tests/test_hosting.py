"""Hosting regressions: all console sockets are mocks; no PS5 is contacted."""
import importlib.util
import http.client
import json
from pathlib import Path
import subprocess
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch
import uuid

SITE = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


server = load('hosting_server', SITE / 'server/server.py')
installer = load('hosting_installer', SITE / 'deploy/install.py')


class DeliveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root_patch = patch.object(server, 'ROOT', SITE / 'release')
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)
        self.collector = server.Collector(('127.0.0.1', 0), self.temporary.name,
                                          public_origin='https://marwanmohamed.ca')
        self.addCleanup(self.collector.server_close)
        self.session = str(uuid.uuid4())
        self.target = '10.0.0.30'
        self.handler = object.__new__(server.Handler)
        self.handler.server = self.collector
        self.handler.hv_client = MagicMock(return_value=self.target)
        self.handler.respond = MagicMock(side_effect=lambda status, value: (status, value))
        self.body = {'firmware': '13.60', 'elfldr_ready': True, 'relapse_session_id': self.session}
        self.socket = MagicMock()
        self.connection = patch.object(server.socket, 'create_connection', return_value=self.socket)
        self.connect = self.connection.start()
        self.addCleanup(self.connection.stop)

    def ready(self, target=None, session=None):
        self.collector.observe_relapse(target or self.target, session or self.session, '13.60',
                                      [{'message': server.RELAPSE_START}, {'message': server.RELAPSE_READY}])

    def test_cannot_send_before_completion(self):
        self.assertEqual(self.handler.send_hv_payload(self.body)[0], 409)
        self.connect.assert_not_called()

    def test_start_or_loader_message_does_not_grant_readiness(self):
        self.collector.observe_relapse(self.target, self.session, '13.60',
                                      [{'message': server.RELAPSE_START}, {'message': 'elfldr is listening on port 9021'}])
        self.assertEqual(self.handler.send_hv_payload(self.body)[0], 409)
        self.connect.assert_not_called()

    def test_ready_without_matching_start_is_rejected(self):
        self.collector.observe_relapse(self.target, self.session, '13.60', [{'message': server.RELAPSE_READY}])
        self.assertIsNone(self.collector.current_relapse(self.target))

    def test_exact_payload_sent_once_and_write_side_closed(self):
        self.ready()
        first = self.handler.send_hv_payload(self.body)
        second = self.handler.send_hv_payload(self.body)
        self.assertEqual((first[0], second[0]), (200, 409))
        self.connect.assert_called_once_with((self.target, 9021), timeout=5)
        console = self.socket.__enter__.return_value
        console.sendall.assert_called_once_with((SITE / 'release/private/hv/byepervisor_reborn.elf').read_bytes())
        console.shutdown.assert_called_once_with(server.socket.SHUT_WR)
        self.assertFalse(first[1]['hv_confirmed'])

    def test_failed_send_stays_consumed(self):
        self.ready()
        self.socket.__enter__.return_value.sendall.side_effect = TimeoutError('partial write')
        self.assertEqual(self.handler.send_hv_payload(self.body)[0], 502)
        self.assertEqual(self.handler.send_hv_payload(self.body)[0], 409)
        self.assertEqual(self.collector.current_relapse(self.target)['transfer_state'], 'uncertain')
        self.connect.assert_called_once()

    def test_replayed_completion_does_not_unlock_attempt(self):
        self.ready()
        self.handler.send_hv_payload(self.body)
        self.collector.observe_relapse(self.target, self.session, '13.60', [{'message': server.RELAPSE_READY}])
        self.assertEqual(self.handler.send_hv_payload(self.body)[0], 409)

    def test_other_console_and_stale_session_are_rejected(self):
        self.ready(target='10.0.0.31')
        self.assertEqual(self.handler.send_hv_payload(self.body)[0], 409)
        self.ready(session=str(uuid.uuid4()))
        self.assertEqual(self.handler.send_hv_payload(self.body)[0], 409)
        self.connect.assert_not_called()

    def test_readiness_expires(self):
        self.ready()
        self.collector.relapse_runs[self.target]['ready_at'] -= server.HV_READY_TTL + 1
        self.assertEqual(self.handler.send_hv_payload(self.body)[0], 409)
        self.connect.assert_not_called()

    def test_wrong_firmware_cannot_grant_readiness(self):
        self.collector.observe_relapse(self.target, self.session, '13.20',
                                      [{'message': server.RELAPSE_START}, {'message': server.RELAPSE_READY}])
        self.assertIsNone(self.collector.current_relapse(self.target))

    def test_payload_drift_prevents_any_socket_connection(self):
        self.ready()
        bad = Path(self.temporary.name) / 'bad.elf'
        bad.write_bytes(b'\x7fELFwrong build')
        self.handler.hv_payload = lambda: bad
        self.assertEqual(self.handler.send_hv_payload(self.body)[0], 503)
        self.connect.assert_not_called()

    def test_hosting_drift_prevents_any_socket_connection(self):
        self.ready()
        with patch.object(server, 'source_version', return_value={'revision': 'changed'}):
            self.assertEqual(self.handler.send_hv_payload(self.body)[0], 409)
        self.connect.assert_not_called()

    def test_concurrent_request_cannot_replay_transfer(self):
        self.ready()
        entered = threading.Event()
        release = threading.Event()

        def delayed_send(_payload):
            entered.set()
            if not release.wait(3):
                raise TimeoutError('test timeout')

        self.socket.__enter__.return_value.sendall.side_effect = delayed_send
        thread = threading.Thread(target=lambda: self.handler.send_hv_payload(self.body))
        thread.start()
        try:
            self.assertTrue(entered.wait(3))
            self.assertEqual(self.handler.send_hv_payload(self.body)[0], 409)
            self.connect.assert_called_once()
        finally:
            release.set()
            thread.join(3)
        self.assertFalse(thread.is_alive())

    def test_fingerprint_covers_the_served_loader_and_core(self):
        fingerprint = server.source_version()['files']
        for name in ('web/relapse/src/relapse_exploit.js', 'web/relapse/offsets/13.60.js',
                     'web/relapse/payloads/elfldr-ps5-1360.elf'):
            self.assertIn(name, fingerprint)


class InstallerTests(unittest.TestCase):
    def test_failed_service_check_restores_all_three_configs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            deploy = root / 'deploy'
            deploy.mkdir()
            (deploy / 'ps5-research.conf').write_text('new snippet')
            (deploy / 'ps5-research.service').write_text('new unit')
            config, snippet, unit = (root / name for name in ('nginx.conf', 'snippet.conf', 'unit.service'))
            for path in (config, snippet, unit):
                path.write_text('old ' + path.name)
            backup = root / 'backup'
            backup.mkdir()

            def command(*args):
                if args == ('systemctl', 'is-active', '--quiet', 'ps5-research.service'):
                    raise subprocess.CalledProcessError(1, args)

            with patch.object(installer, 'ROOT', root), patch.object(installer, 'command', side_effect=command), \
                    patch.object(installer.subprocess, 'run', return_value=MagicMock(returncode=0)):
                with self.assertRaises(subprocess.CalledProcessError):
                    installer.apply_configuration(config, snippet, unit, backup, 'new config')
            for path in (config, snippet, unit):
                self.assertEqual(path.read_text(), 'old ' + path.name)

    def test_failed_first_install_removes_new_unit_and_snippet(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'deploy').mkdir()
            (root / 'deploy/ps5-research.conf').write_text('new snippet')
            (root / 'deploy/ps5-research.service').write_text('new unit')
            config, snippet, unit = (root / name for name in ('nginx.conf', 'snippet.conf', 'unit.service'))
            config.write_text('old config')
            backup = root / 'backup'
            backup.mkdir()
            calls = []

            def command(*args):
                calls.append(args)
                if len(calls) == 1:
                    raise RuntimeError('nginx validation failed')

            with patch.object(installer, 'ROOT', root), patch.object(installer, 'command', side_effect=command), \
                    patch.object(installer.subprocess, 'run', return_value=MagicMock(returncode=1)):
                with self.assertRaises(RuntimeError):
                    installer.apply_configuration(config, snippet, unit, backup, 'new config')
            self.assertEqual(config.read_text(), 'old config')
            self.assertFalse(snippet.exists())
            self.assertFalse(unit.exists())
            self.assertIn(('systemctl', 'stop', 'ps5-research.service'), calls)
            self.assertIn(('systemctl', 'disable', 'ps5-research.service'), calls)


class HttpWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = patch.object(server, 'ROOT', SITE / 'release')
        self.root.start()
        self.addCleanup(self.root.stop)
        self.collector = server.Collector(('127.0.0.1', 0), self.temporary.name,
                                          public_origin='https://marwanmohamed.ca')
        self.thread = threading.Thread(target=self.collector.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop)
        self.transport = MagicMock()
        self.socket_patch = patch.object(server, 'socket', SimpleNamespace(create_connection=self.transport, SHUT_WR=1))
        self.socket_patch.start()
        self.addCleanup(self.socket_patch.stop)
        self.session = str(uuid.uuid4())

    def stop(self):
        self.collector.shutdown()
        self.collector.server_close()
        self.thread.join(3)

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.collector.server_port, timeout=3)
        request_headers = {'Host': 'marwanmohamed.ca', 'Origin': 'https://marwanmohamed.ca',
                           'User-Agent': 'Mozilla/5.0 (PlayStation; PlayStation 5/13.60)',
                           'X-Real-IP': '10.0.0.30', 'Content-Type': 'application/json'}
        request_headers.update(headers or {})
        try:
            if isinstance(body, bytes):
                request_headers.pop('Content-Type', None)
                encoded = body
            else:
                encoded = json.dumps(body) if body is not None else None
            connection.request(method, '/ps5' + path, encoded, request_headers)
            response = connection.getresponse()
            payload = response.read()
            return response.status, (json.loads(payload) if response.getheader('Content-Type', '').startswith('application/json') else payload)
        finally:
            connection.close()

    def completion(self):
        return {'session_id': self.session, 'firmware': '13.60', 'lines': [
            {'seq': 1, 'level': 'info', 'message': server.RELAPSE_START, 'client_time': server.stamp()},
            {'seq': 2, 'level': 'success', 'message': server.RELAPSE_READY, 'client_time': server.stamp()},
        ]}

    def test_durable_completion_to_single_send_over_actual_http(self):
        self.assertFalse(self.request('GET', '/api/hv/status')[1]['relapse_ready'])
        completion = self.completion()
        self.assertEqual(self.request('POST', '/api/relapse/diagnostics', completion)[0], 200)
        status, ready = self.request('GET', '/api/hv/status')
        self.assertEqual(status, 200)
        self.assertEqual(ready['relapse_session_id'], self.session)
        body = {'firmware': '13.60', 'elfldr_ready': True, 'relapse_session_id': self.session}
        self.assertEqual(self.request('POST', '/api/hv/send', body)[0], 200)
        self.assertEqual(self.request('POST', '/api/hv/send', body)[0], 409)
        # An idempotent diagnostics retry must not grant another send.
        self.assertEqual(self.request('POST', '/api/relapse/diagnostics', completion)[0], 200)
        self.assertFalse(self.request('GET', '/api/hv/status')[1]['relapse_ready'])
        self.transport.assert_called_once()

    def test_rejected_or_unstored_completion_does_not_grant_readiness(self):
        self.assertEqual(self.request('POST', '/api/relapse/diagnostics', self.completion(),
                                     {'Origin': 'https://unrelated.example'})[0], 403)
        self.assertEqual(self.request('GET', '/api/hv/status', headers={'X-Real-IP': '192.0.2.1'})[0], 403)
        self.collector.max_storage_bytes = 0
        self.assertEqual(self.request('POST', '/api/relapse/diagnostics', self.completion())[0], 507)
        self.assertFalse(self.request('GET', '/api/hv/status')[1]['relapse_ready'])
        self.transport.assert_not_called()

    def test_dump_upload_is_session_bound_assembled_and_downloadable(self):
        common = {'X-Session': self.session, 'X-Filename': 'kernel_base.json', 'Content-Length': '49'}
        base = b'{"firmware":"13.60","kernel_base":"0xffffffff8a9c0000"}'
        common['Content-Length'] = str(len(base))
        self.assertEqual(self.request('POST', '/dump', base, common)[0], 200)
        raw = bytes(server.MAX_DUMP_FILE_BYTES)
        for index in range(8):
            chunk = raw[index * 4096:(index + 1) * 4096]
            status, ack = self.request('POST', '/dump', chunk, {
                'X-Session': self.session, 'X-Filename': 'sysent_raw.bin',
                'X-Chunk': f'{index + 1}/8'})
            self.assertEqual(status, 200)
            if index == 7:
                self.assertTrue(ack['complete'])
        status, index_file = self.request('GET', f'/api/dump/{self.session}/sysent_index.json')
        self.assertEqual(status, 200)
        self.assertEqual(len(index_file['entries']), 679)
        self.assertEqual(index_file['entries'][0]['num'], 0)
        status, result = self.request('GET', f'/api/dump/status?session_id={self.session}')
        self.assertEqual(status, 200)
        self.assertTrue(result['complete'])

    def test_dump_rejects_unknown_file_wrong_firmware_and_unbound_session(self):
        base = b'{"firmware":"14.10","kernel_base":"0xffffffff8a9c0000"}'
        headers = {'X-Session': self.session, 'X-Filename': 'kernel_base.json'}
        self.assertEqual(self.request('POST', '/dump', base, headers)[0], 400)
        headers['X-Filename'] = '../events.jsonl'
        self.assertEqual(self.request('POST', '/dump', base, headers)[0], 400)
        headers['X-Session'] = str(uuid.uuid4())
        self.assertEqual(self.request('GET', f'/api/dump/{headers["X-Session"]}/sysent_raw.bin')[0], 404)

    def test_unified_page_has_one_relapse_action_and_explicit_hv_pause(self):
        status, page = self.request('GET', '/')
        self.assertEqual(status, 200)
        page = page.decode('utf-8') if isinstance(page, bytes) else page
        self.assertIn('Save the syscall table during this run', page)
        self.assertIn('Byepervisor / Rest Mode is paused', page)
        self.assertIn('Start Relapse', page)
        self.assertLess(page.index('relapse/src/firmware.js'), page.index('relapse/launch.js'))
        self.assertNotIn('continue-hv', page)

    def test_legacy_relapse_route_serves_same_unified_document(self):
        status, page = self.request('GET', '/relapse/')
        self.assertEqual(status, 200)
        if isinstance(page, bytes):
            page = page.decode('utf-8')
        self.assertIn('One page. One run at a time.', page)

    def test_relapse_asset_route_is_static_and_offsets_are_relative_to_relapse(self):
        config = (SITE / 'deploy/ps5-research.conf').read_text(encoding='utf-8')
        main = (SITE / 'web/relapse/src/main.js').read_text(encoding='utf-8')
        self.assertIn('location ^~ /ps5/relapse/', config)
        self.assertIn('alias /var/www/ps5-research/web/relapse/', config)
        self.assertIn('new URL("../", document.currentScript.src)', main)
        self.assertIn('new URL(`offsets/${window.fw_str}.js?', main)
        self.assertIn('new URL("src/utils/rop_slave.js", relapseAssetBase)', main)
        kexp = (SITE / 'web/relapse/src/kexp.js').read_text(encoding='utf-8')
        self.assertIn('new URL("../payloads/" + name, import.meta.url)', kexp)
        extract = (SITE / 'web/relapse/src/extract.js').read_text(encoding='utf-8')
        self.assertIn('RECEIVER: "../../dump"', extract)
        status, css = self.request('GET', '/research.css')
        self.assertEqual(status, 200)
        self.assertIn(b'#254534', css)


if __name__ == '__main__':
    unittest.main()
