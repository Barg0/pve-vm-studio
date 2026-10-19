"""cisv studio: the Studio's own API, signed in as a PVE user - bakes, settings, gold reports.

Credentials come from a JSON file outside the repo (default /root/.cisv/studio.json, mode 600):
    {"url": "https://<studio host>", "username": "root@pam", "password": "..."}
TLS is verified; use the name the Studio's certificate carries, not its IP.
"""
import http.cookiejar
import json
import os
import stat
import sys
import urllib.error
import urllib.request
from pathlib import Path

from .log import log

CRED = Path(os.environ.get('CISV_STUDIO_CRED', '/root/.cisv/studio.json'))


class Studio:
    def __init__(self, cred=CRED):
        if not cred.exists():
            raise SystemExit(f'no Studio credentials at {cred}')
        if cred.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise SystemExit(f'{cred} is readable by others - chmod 600 it')
        c = json.loads(cred.read_text())
        self.url = c['url'].rstrip('/')
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        s = self._call('POST', '/api/session', {'username': c['username'], 'password': c['password']}, csrf=False)
        self.csrf = s['csrf']
        log('ok', f'signed in to {self.url} as {s["user"]} (build {s.get("build", "?")})')

    def _call(self, method, path, body=None, csrf=True):
        data = None if body is None else json.dumps(body).encode()
        rq = urllib.request.Request(self.url + path, data=data, method=method)
        if data is not None:
            rq.add_header('Content-Type', 'application/json')
        if csrf and method != 'GET':
            rq.add_header('x-pvs-csrf', self.csrf)
        try:
            with self.op.open(rq, timeout=120) as r:
                raw = r.read()
        except urllib.error.HTTPError as e:
            raise SystemExit(f'{method} {path}: HTTP {e.code} {e.read().decode(errors="replace")[:500]}')
        return json.loads(raw) if raw.strip() else None

    def get(self, path):
        return self._call('GET', path)

    def put(self, path, body):
        return self._call('PUT', path, body)

    def post(self, path, body):
        return self._call('POST', path, body)

    def delete(self, path):
        return self._call('DELETE', path)

    def job_log(self, job):
        """A job's log lines, from its event stream (it ends on its own for a finished job)."""
        rq = urllib.request.Request(f'{self.url}/api/jobs/{job}/events')
        with self.op.open(rq, timeout=120) as r:
            for raw in r:
                line = raw.decode(errors='replace').rstrip('\r\n')
                if not line.startswith('data:'):
                    continue
                try:
                    ev = json.loads(line[5:])
                except ValueError:
                    continue
                if isinstance(ev, dict) and 'text' in ev and 'n' in ev:
                    yield ev['text']
                elif isinstance(ev, dict) and 'status' in ev:
                    return


def cmd_studio(cfg, args):
    s = Studio()
    if args.method == 'log':
        for t in s.job_log(args.path):
            print(t)
        return 0
    body = json.loads(args.body) if args.body else None
    r = {'get': lambda: s.get(args.path), 'put': lambda: s.put(args.path, body),
         'post': lambda: s.post(args.path, body), 'delete': lambda: s.delete(args.path)}[args.method]()
    json.dump(r, sys.stdout, indent=1)
    print()
    return 0
