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
import pickle
from urllib.parse import unquote

import libtorrent as lt
from ip2geotools.databases.noncommercial import DbIpCity


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

official_ips = {
    "198.74.49.126",
    "45.79.68.96",
    "172.233.188.196",
    "198.58.97.108",
    "45.33.90.133",
    "172.233.129.94",
    "96.126.113.96",
}

known_clients = {}

def connect_to_network():
    global official_ips, known_clients

    listening_port = 2377

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

    if os.path.isfile("known_clients.dump"):
        with open("known_clients.dump", "rb") as f:
            known_clients = pickle.loads(f.read())

    print("Starting...")
    while (not s.is_seeding):
        s = h.status()

        peer_info = h.get_peer_info()
        official_peers = len([peer for peer in peer_info if peer.ip[0] in official_ips])
        print(f"{official_peers} official peers are alive.")
        for peer in peer_info:
            ip, port = peer.ip
            if ip in official_ips:
                continue
            if ip not in known_clients:
                location = DbIpCity.get(ip, api_key='free')
                known_clients[ip] = (location.city, location.region, location.country, port, peer.client)
            else:
                city, region, country, _, original_client = known_clients[ip]
                if original_client != peer.client and peer.client:
                    print(f"{ip}.client: {original_client} -> {peer.client}")
                    known_clients[ip] = (city, region, country, port, peer.client)

        # dump everything
        with open("known_clients.dump", "wb") as f:
            f.write(pickle.dumps(known_clients))

        i = 1
        for ip, (city, region, country, port, client) in known_clients.items():
            print(f"{i} - Location: {city} {region} {country}, IP: {ip}, port: {port}, client: {client}")
            i += 1

        alerts = ses.pop_alerts()
        for a in alerts:
            # ignore all alerts
            pass

        print("Sleeping...")
        time.sleep(10)


def main():
    connect_to_network()


if __name__ == "__main__":
    main()

