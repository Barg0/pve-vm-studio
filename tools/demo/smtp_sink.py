#!/usr/bin/env python3
"""A smart host for the demo: speaks enough SMTP to take a mail and answer like Postfix.
Accepts everything except recipients starting with "reject@" (550) or "later@" (451), and
keeps nothing.

    python3 tools/demo/smtp_sink.py [--port 2525]
"""
import argparse, random, socketserver, string


class H(socketserver.StreamRequestHandler):
    def say(self, line):
        self.wfile.write((line + "\r\n").encode())

    def handle(self):
        self.say("220 pmg.lab.example ESMTP Postfix")
        data = False
        while True:
            raw = self.rfile.readline()
            if not raw:
                return
            line = raw.decode(errors="replace").rstrip("\r\n")
            if data:
                if line == ".":
                    data = False
                    qid = "".join(random.choices(string.ascii_uppercase + string.digits, k=10))
                    self.say(f"250 2.0.0 Ok: queued as {qid}")
                continue
            cmd = line[:4].upper()
            if cmd in ("EHLO", "HELO"):
                self.say("250-pmg.lab.example")
                self.say("250-SIZE 10240000")
                self.say("250-8BITMIME")
                self.say("250 SMTPUTF8")
            elif cmd == "MAIL":
                self.say("250 2.1.0 Ok")
            elif cmd == "RCPT":
                to = line.split(":", 1)[1].strip().strip("<>").lower()
                if to.startswith("reject@"):
                    self.say("550 5.1.1 <%s>: Recipient address rejected: User unknown in virtual mailbox table" % to)
                elif to.startswith("later@"):
                    self.say("451 4.7.1 <%s>: Recipient address rejected: Greylisted, see https://postgrey.schweikert.ch/" % to)
                else:
                    self.say("250 2.1.5 Ok")
            elif cmd == "DATA":
                data = True
                self.say("354 End data with <CR><LF>.<CR><LF>")
            elif cmd == "RSET":
                self.say("250 2.0.0 Ok")
            elif cmd == "QUIT":
                self.say("221 2.0.0 Bye")
                return
            else:
                self.say("502 5.5.2 Error: command not recognized")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=2525)
    a = ap.parse_args()
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer(("127.0.0.1", a.port), H) as srv:
        print(f"SMTP sink on 127.0.0.1:{a.port}", flush=True)
        srv.serve_forever()
