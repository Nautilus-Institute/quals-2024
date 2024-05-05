import time
import sys
import base64
import tempfile
import os
import http.server
import socketserver
import threading
import urllib
import posixpath
from urllib.parse import unquote

import libtorrent as lt


BOOTSTRAP = """ZDg6YW5ub3VuY2U0Mjp1ZHA6Ly90cmFja2VyLm9wZW50cmFja3Iub3JnOjEzMzcvYW5ub3VuY2U3
OmNvbW1lbnQyNjpGb3IgYm9vdHN0cmFwcGluZyBwdXJwb3NlczEwOmNyZWF0ZWQgYnkxODpxQml0
dG9ycmVudCB2NC42LjQxMzpjcmVhdGlvbiBkYXRlaTE3MTQ3MjQ4ODllNDppbmZvZDY6bGVuZ3Ro
aTEwNDg1NzYwMGU0Om5hbWUxMzpib290c3RyYXAuYmluMTI6cGllY2UgbGVuZ3RoaTgzODg2MDhl
NjpwaWVjZXMyNjA6COsY1AOMDCNOjFZbomhIoKYnSWKskTQn9zDYl/ximNKvkkCwyrKhc+17NLZV
+7p8y/iIgb4DkLGvg8c+dJKxIIQIUck+iRtk2ilru33KTTGtsrOkL+JbAiPfjaKqJ3yqrurY+lqG
OodePcer/4ZjAlcmVMMbKxayfP7U9u9ZbjcCifAskVDGdcLO0mXwCN/2MvQJW8vfH5sbIqvjnt0/
OWAAaQyb/Orfm/fxIVOwmpnGCcwohvHn2uvzP/NRtV3YPAPOBryfqgRR0x0afuz0whN7WLl66dtm
KtbcgMu3yyJWlbUdeycIlUbwsmFhG0sDIN3d/BRg/kT7kEELsM7HGadv2BU3OnByaXZhdGVpMWVl
ZQ=="""


def connect_to_network():
    listening_port = 9999

    ses = lt.session({
        'listen_interfaces': f'0.0.0.0:{listening_port}',
        'enable_dht': False,
        'enable_upnp': False,
        # "alert_mask": lt.alert_category.all,
    })

    torrent = base64.b64decode(BOOTSTRAP.replace("\n", "").encode("utf-8"))
    info = lt.torrent_info(torrent)
    h = ses.add_torrent({'ti': info, 'save_path': tempfile.gettempdir(), "flags": 0x20})
    h.set_download_limit(5000)
    h.set_upload_limit(5000)
    s = h.status()

    while (not s.is_seeding):
        s = h.status()

        peer_info = h.get_peer_info()

        alerts = ses.pop_alerts()
        for a in alerts:
            # ignore all alerts
            pass

        time.sleep(10)


class MyHttpRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        """Handle GET requests."""
        path = unquote(self.path).strip('/')
        if path.startswith("download?file="):
            # implement the missing feature in nirai-py to match the feature in nirai-cpp
            real_path = path[15:]
            self.send_response(200)
            if ".." in real_path:
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(f"Attacking attempt detected.\n".encode("utf-8"))
                return
            if real_path.startswith("/"):
                # remove the leading /
                real_path = real_path[1:]
                # handle more leading /s
                stripped_path = real_path
                while stripped_path.startswith("/"):
                    stripped_path = stripped_path[1:]
                rel_path = stripped_path
            self.send_header("Content-type", "application/octet")
            self.end_headers()
            if os.path.isfile(real_path):
                with open(real_path, "rb") as f:
                    data = f.read()
                self.wfile.write(data)
            return

        # Decode URL and strip leading '/'
        path = unquote(path).strip('/')
        if not path:
            path = "."

        # Check if the path is a directory
        if os.path.isdir(path):

            # List all files and directories in the current path
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()

            # no path traversal!
            if ".." in path:
                self.wfile.write(f"Attacking attempt detected.\n".encode("utf-8"))
                return

            self.wfile.write(f"<html><head>".encode("utf-8"))
            self.wfile.write(f"<title>nirai-py webui - Directory Listing</title></head>".encode('utf-8'))
            self.wfile.write(f"<body><h1>Directory Listing of {path}</h1><ul>".encode('utf-8'))

            for item in os.listdir(path):
                item_path = os.path.join(path, item)
                if os.path.isdir(item_path):
                    self.wfile.write(f"<li>Directory: <a href='/{item_path}'>{item}</a></li>".encode('utf-8'))
                else:
                    self.wfile.write(f"<li>File: {item}</li>".encode('utf-8'))

            self.wfile.write("</ul></body></html>".encode('utf-8'))
        else:
            self.path = self.path.strip('.')
            # Serve files normally
            super().do_GET()

    def translate_path(self, path):
        """Translate a /-separated PATH to the local filename syntax.

        Components that mean special things to the local file system
        (e.g. drive or directory names) are ignored.  (XXX They should
        probably be diagnosed.)

        """
        # abandon query parameters
        path = path.split('?',1)[0]
        path = path.split('#',1)[0]
        # Don't forget explicit trailing slash when normalizing. Issue17324
        trailing_slash = path.rstrip().endswith('/')
        try:
            path = urllib.parse.unquote(path, errors='surrogatepass')
        except UnicodeDecodeError:
            path = urllib.parse.unquote(path)
        path = posixpath.normpath(path)
        words = path.split('/')
        words = filter(None, words)
        path = self.directory if not path.startswith("/") else "/"
        for word in words:
            if os.path.dirname(word) or word in (os.curdir, os.pardir):
                # Ignore components that are not a simple file/directory name
                continue
            path = os.path.join(path, word)
        if trailing_slash:
            path += '/'
        return path


def start_web_server():

    PORT = 8000
    HOST = "127.0.0.1"
    if os.path.isfile("/webui_bind_global"):
        HOST = "0.0.0.0"

    # Set up the server
    handler = MyHttpRequestHandler
    with socketserver.TCPServer((HOST, PORT), handler) as httpd:
        httpd.serve_forever()


def main():
    if os.path.exists("/web_server"):
        th = threading.Thread(target=start_web_server, daemon=True)
        th.start()
    connect_to_network()
    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()

