# nirai

# Challenge Type

reversing/pwn/web/misc

# Difficulty Level

- Flag 1: Low
- Flag 2: Medium
- Flag 3: Medium
- Flag 4: Hard

## Features

nirai features two clients: nirai-py and nirai-cpp.
Each client implements a torrenting component (based on libtorrent) and a webUI component.

### Torrenting

The torrenting component has a custom extension `ni_exchangeflag`.
It has two features:

1. Requesting and sending flags from the client with a flag configured (this is Flag 2; the flag is at `/exchange_flag`).
2. Requesting files from the current working directory (not vulnerable to path traversal).

### Web UI

The webUI component implements the following features:

nirai-cpp:

- File downloading: `/download?file=` (vulnerable to path traversal without ".."). This is Flag 1; the flag is at `/flag`.
- Peer listing: `/peers`.
- Setting peer nicknames: `/peer_set_nick?nick=` (vulnerable to the libc iconv() bug).

nirai-py:

- Directory listing: `/` lists content within directories.
- File downloading: `/<file_path>`. Vulnerable to path traversal. This is Flag 3; the flag is at `/flag`.

## Vulnerabilities & Attack Vectors

### Flag 1

- Figure out the default username and password by reversing the binary.
  The default credentials are `nirai_admin:G27E3FCGFGE5D37DC3G78733:FE69G37`.
- A nirai-cpp client is misconfigured and listens at `0.0.0.0:8899`. This is Flag 1.

### Flag 2

Players reverse and understand how the flag should be requested and sent back from the `ni_exchangeflag` plugin.
Figure out which client to target.
Send the request and get the encoded flag.
Should be a pure reversing challenge.

### Flag 3

Several nirai-py clients (those with `remote_debug` on, set by `/debug`) each holds a piece of the flag at `/flag_chunk`.

- The Python-version of the web UI is vulnerable to path traversal, but it is only accessible from localhost.
- The debug protocol of the extension allows a remote user to access http:// resources.
- Players can use path traversal to access `/flag_chunk` and download them. Collecting all of them gives you the flag.

### Flag 4

Leak the `nirai-cpp-v2` executable.
Note that it's going to be difficult to fully leak it (due to the request limit in the plugin).
Players will have to "leak and reverse"; leak enough of the executable, reverse it, figure out where to leak next.
Then use the iconv() vulnerability (CVE-2024-2961) to bypass the login check.

## Configurations

Most configurations are done through files on the file system.

- `/exchange_flag`: Enable the exchange-flag feature of the `ni_exchangeflag` extension.
- `/debug`: Enable the remote-debugging feature of the `ni_exchangeflag` extension.
- `/web_server`: Enable the web UI feature.
- `/webui_bind_global`: Configure if the web server should bind to `0.0.0.0` (`127.0.0.1` by default).
- `/web_server_port`: Configure the port for the web server.
- `/web_server_user`: Configure the username for the web server.
- `/web_server_password`: Configure the password for the web server.


## Deployment

This section is only for Fish to use as a reference!

### nirai-flag-1

IP: `45.79.68.96`
Flag: `flag{PPTqHtVOpASHkznGQzC1_potluck_of_the_internet}`

- Variant: nirai-cpp-v1
- Default credentials for web UI: `/web_server` exists; `/webui_bind_global` exists; `/web_server_port` = 8000; No `/web_server_user` or `/web_server_password`.
- The flag is at `/flag`.
- No `/exchange_flag`.
- No `/debug`.

### nirai-flag-2

IP: `172.233.188.196`
Flag: `flag{P7erxKO4ts7XiaelY41Z_flag_distribution_0n_ster0ids!}`

- Variant: nirai-py
- Web UI is turned off: No `/web_server`; No `/web_server_listen_global`; No `/web_server_port`; No `/web_server_user` or `/web_server_password`.
- The flag is at `/exchange_flag`.
- No `/debug`.
- No `/flag`.

### nirai-flag-3

IP-a: `198.58.97.108`

IP-b: `45.33.90.133`

IP-c: `172.233.129.94`

Flag: `flag{vXeaGszrxUvMHRwsZ6gO_p2p_4_the_win_MgF22xuMyK1avl1ocrYC}`
Chunk 1: `flag{vXeaGszrxUvMHRws`
Chunk 2: `Z6gO_p2p_4_the_win_Mg`
Chunk 3: `F22xuMyK1avl1ocrYC}`

- Variant: nirai-py
- No credentails for web UI: `/web_server` exists; `/webui_bind_global` does not exist; `/web_server_port` = 8000; `/web_server_user` and `/web_server_password` are both empty.
- No `/exchange_flag`.
- `/debug` exists.
- Flag is split into three chunks stored inside `/flag_chunk`.

### nirai-flag-4

IP: `96.126.113.96`
Flag: `flag{kncRG8zInMWEhnKPt8XG_did_u_fuzz_glibc_today?}`

- Variant: nirai-cpp-v2
- Strong credentials for web UI: `/web_server` exists; `/webui_bind_global` exists; `/web_server_port` = 8000; `/web_server_user` and `/web_server_password` are both of strong passwords.
- No `/exchange_flag`.
- `/debug` exists.
- Flag is stored at `/flag`.
- IMPORTANT: Ensure that the glibc is vulnerable! `libc6_2.35-0ubuntu3.6` is vulnerable while `libc6_2.35-0ubuntu3.7` is not. Apparently Canonical pushed an update during this weekend...
- IMPORTANT: Disable the apt unattended-update feature...

## Challenge Descriptions

### nirai-1

You are in 2016...
Something is weird on one of the nodes...
The brave Nautilus Institute investigators acquired the IP of the weird node: `45.79.68.96`.
Figure it out.

Downloads: `nirai-cpp-v1`.

### nirai-2

You are still in 2016...
Something is super weird on another node, but unlike the last one, it is not as noisy...
The brave Nautilus Institute investigators acquired the IP of the weird node: `172.233.188.196`.
Figure it out.

Downloads: `libtorrent-raster.so`

### nirai-3

Unfortunately, you are stuck in 2016...
More IP addresses for you to investigate: `198.58.97.108`, `45.33.90.133`, and `172.233.129.94`.
Obtain a flag as the proof of your investigation!

### nirai-4

All of a sudden, you are teleported from 2016 to May 2024!
Get the flag from `96.126.113.96`.

