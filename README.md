# slinex_ctrl.pl

A command-line tool for controlling **Slinex** video intercoms over the local network via the proprietary **OWSP** binary protocol. Supports lock control, live video, two-way audio intercom, device info, and push-notification monitoring — all without the official mobile app.

---

## Features

| Command | Description |
|---------|-------------|
| `unlock` | Open the door lock |
| `lock` | Close the door lock |
| `info` | Query device UID, model, hardware, firmware, date/time |
| `keepalive` | Probe device reachability (no login required) |
| `video` | Stream live H.264 video to **mpv** |
| `intercom` | Full-duplex G.711 audio intercom via **arecord** / **aplay** |
| `notify` | Subscribe to doorbell ring events via MQTT (no intercom IP needed) |

### Protocol details

- **Transport:** TCP, default port `34567`
- **Framing:** OWSP — 8-byte header (`packet_length` BE u32 + `seq` LE u32) followed by one or more TLV records (type LE u16 + length LE u16 + body)
- **Login formats:** v5.0 `LoginRequestEx` (68-byte body) and v3.7 `LoginRequest` (56-byte body); the script tries v5.0 first and falls back to v3.7 automatically
- **Password encryption:** XOR with `lbtech` key + 25 bias (`Encrypt.EncrypKey` from the APK)
- **Video:** H.264 Annex-B; I-frames (TLV 100) and P-frames (TLV 101) piped directly to mpv
- **Audio codec:** G.711 μ-law (waveFormat `0x7A25`) or A-law (`0x7A19`); format negotiated via `TalkResponse` (TLV 332)
- **Push notifications:** MQTT 3.1.1 over TCP to `mobileeyedoor.push2u.com:1883`, topic `GoMDP/#`; ring events contain `[Ringing]` in the payload

---

## Requirements

### Runtime

- **Perl 5.10+** (uses `//` defined-or operator)
- Standard Perl modules only — **no CPAN dependencies**:
  - `IO::Socket::INET`
  - `IO::Select`
  - `Getopt::Std`

### Optional external tools

| Tool | Required for |
|------|-------------|
| `mpv` | `video` command |
| `aplay` | `intercom` command (audio playback) |
| `arecord` | `intercom` command (microphone capture) |

On Debian/Ubuntu:

```bash
sudo apt install mpv alsa-utils
```

On Arch Linux:

```bash
sudo pacman -S mpv alsa-utils
```

---

## Installation

```bash
git clone https://github.com/ashevchuk/slinex_xr-30ip.git
cd slinex_xr-301p
chmod +x slinex_ctrl.pl
```

No build step required.

---

## Usage

```
perl slinex_ctrl.pl [options] <command>

Options:
  -h <host>    Intercom IP address (required for most commands)
  -p <port>    TCP port (default: 34567)
  -u <user>    Username (default: admin)
  -w <pass>    Login password (default: empty)
  -l <pwd>     Lock password (default: same as -w)
  -c <ch>      Channel 0–7 (default: 0)
  -d <sec>     Lock open duration in seconds (default: 5)
  -t <sec>     TCP connect/read timeout (default: 10)
  -o           Force old login format (v3.7, 56 bytes)
  -a           Include audio track in video mode
  -e <cmd>     Shell command to run on each ring event (notify mode)
  -v           Verbose output — prints TLV types, hex packet dumps
```

---

## Examples

### Check device reachability

```bash
perl slinex_ctrl.pl -h 192.168.1.100 keepalive
```

### Query device information

```bash
perl slinex_ctrl.pl -h 192.168.1.100 -u admin -w secret info
```

Output:

```
Login: user='admin' format=v5.0 ...
Logged in.
Device information (from login):
  UID:        ABCDEF1234567890
  Model:      SL-IP-12
  Hardware:   1.1
  Firmware:   3.218.0000.0.R
  Date/Time:  2024-11-15 14:32:07
Done.
```

### Open the door lock

```bash
perl slinex_ctrl.pl -h 192.168.1.100 -u admin -w secret unlock
```

With a separate lock password and custom open duration:

```bash
perl slinex_ctrl.pl -h 192.168.1.100 -w adminpass -l lockpass -d 10 unlock
```

### Close the lock immediately

```bash
perl slinex_ctrl.pl -h 192.168.1.100 -u admin -w secret lock
```

### Watch live video (no audio)

```bash
perl slinex_ctrl.pl -h 192.168.1.100 -u admin -w secret video
```

### Watch live video with audio

```bash
perl slinex_ctrl.pl -h 192.168.1.100 -u admin -w secret -a video
```

mpv opens automatically and reads the H.264 Annex-B stream from stdin. Press `Ctrl+C` to stop.

### Two-way audio intercom

```bash
perl slinex_ctrl.pl -h 192.168.1.100 -u admin -w secret intercom
```

- Microphone is captured via `arecord`, encoded to G.711 μ-law (or A-law, negotiated), and streamed to the device.
- Incoming audio from the device is decoded from G.711 μ-law and played back via `aplay`.
- Uses `fork()` — the child process handles mic capture while the parent handles playback.
- Press `Ctrl+C` to send a `TalkStop` request and exit cleanly.

### Wait for doorbell ring events (MQTT notify)

```bash
perl slinex_ctrl.pl notify
```

This command does **not** connect to the intercom directly. It subscribes to the Slinex MQTT push broker and prints a line whenever any registered device rings.

Filter by a specific device UID:

```bash
perl slinex_ctrl.pl -h ABCDEF1234567890 notify
```

Run a custom command (e.g., send a notification) on each ring:

```bash
perl slinex_ctrl.pl -e 'notify-send "Doorbell" "Someone is at the door"' notify
```

Combine UID filter with a command:

```bash
perl slinex_ctrl.pl -h ABCDEF1234567890 -e '/usr/local/bin/ring_handler.sh' notify
```

The `-e` command is executed via `exec` in a forked child — it does not block ring detection.

### Verbose / debug mode

```bash
perl slinex_ctrl.pl -h 192.168.1.100 -u admin -w secret -v unlock
```

Verbose output includes TLV type/length for every received packet and hex dumps of packet bodies up to 80 bytes.

---

## Protocol reference

### OWSP frame layout

```
Offset  Size  Endian  Field
     0     4      BE  packet_length  (includes these 4 bytes + all TLVs)
     4     4      LE  sequence
     8     …       —  TLV records (one or more)
```

### TLV record layout

```
Offset  Size  Endian  Field
     0     2      LE  type
     2     2      LE  body_length
     4     …       —  body
```

### Known TLV types

| Type | Name | Direction |
|------|------|-----------|
| 40 | VERSION_INFO | S→C |
| 41 | LOGIN_REQ | C→S |
| 42 | LOGIN_RSP | S→C |
| 47 | STOP_STREAM_REQ | C→S |
| 48 | STOP_STREAM_RSP | S→C |
| 49 | KEEPALIVE_REQ | C→S |
| 57 | KEEPALIVE_RSP | S→C |
| 70 | DEVICE_INFO_REQ | C→S |
| 71 | DEVICE_INFO_RSP | S→C |
| 97 | AUDIO_INFO | C→S |
| 98 | AUDIO_DATA | C↔S |
| 99 | VIDEO_FRAME_INFO | S→C |
| 100 | VIDEO_IFRAME | S→C |
| 101 | VIDEO_PFRAME | S→C |
| 199/200/203 | STREAM_FORMAT | S→C |
| 331 | TALK_REQ | C→S |
| 332 | TALK_RSP | S→C |
| 341 | ALARM_REQ (ring) | S→C |
| 342 | ALARM_RSP | C→S |
| 425 | LOCK_REQ | C→S |
| 426 | LOCK_RSP | S→C |

### Login response codes

| Code | Meaning |
|------|---------|
| 1 | OK |
| 2 | Wrong password |
| 4 | Protocol version error |
| 5 | Too many clients |
| 6 | Device unavailable |
| 8 | Device overloaded |
| 9 | Invalid channel |
| 10 | Protocol error |
| 11 | Encoding not started |
| 12 | Task execution error |
| 13 | Configuration error |
| 14 | Talk not supported |
| 17 | Memory error |
| 19 | User not found |
| 22 | Insufficient privileges |
| 35 | Access denied |

### Password encryption

Both login password and lock password are obfuscated using a simple XOR cipher before being placed in the packet body:

```
encrypted[i] = plaintext[i] XOR (key[i % keylen] + 25)
```

where `key = "lbtech"` (6 bytes). The output buffer is zero-padded to 16 bytes (login) or 32 bytes (lock).

### Audio codec

The intercom audio path is:

```
Microphone → PCM s16le 8000 Hz mono → G.711 encode → TLV 97+98 → device
device → TLV 98 → G.711 decode → PCM s16le 8000 Hz mono → Speaker
```

The G.711 codec (both μ-law and A-law) is implemented in pure Perl inside the script — no external codec libraries are needed. The exact codec variant (μ-law `0x7A25` or A-law `0x7A19`) is negotiated in the `TalkResponse` (TLV 332).

---

## Compatibility

Tested against Slinex firmware versions that use protocol v3.7 and v5.0. The script auto-detects the version:

1. Tries v5.0 (`LoginRequestEx`, 68-byte body) first.
2. If the device rejects it, reconnects and retries with v3.7 (`LoginRequest`, 56-byte body).
3. Use `-o` to skip auto-detection and force v3.7 directly.

Known compatible device families: **SL-IP-12**, **SL-IP-15** and other models sold under the Slinex brand that use the GoClient / MobileEyeDoor cloud stack.

---

## Troubleshooting

**`Connection error: Connection refused`**
The device is not reachable on the specified IP/port. Verify the IP address and that port 34567 is open (some firmware versions use a different port — try `-p 34568`).

**`Authentication error: Wrong password`**
Check the login password with `-w`. The default admin password on many devices is empty — try without `-w`.

**`Authentication error: Protocol version error`**
Add `-o` to force the v3.7 login format.

**`No response to TalkRequest`**
Some devices do not support the intercom feature, or the firmware version is incompatible. Check that the device model has a microphone/speaker.

**`Failed to start mpv`**
Install mpv: `sudo apt install mpv` or `sudo pacman -S mpv`.

**`Failed to start aplay` / `arecord`**
Install ALSA utilities: `sudo apt install alsa-utils`. Also verify that your default ALSA input/output devices are configured correctly (`arecord -l`, `aplay -l`).

**Video is choppy or mpv complains about missing keyframes**
The device sends I-frames periodically. The first few seconds may look incomplete until the first I-frame arrives. This is normal.

**`notify` shows no events**
The push broker `mobileeyedoor.push2u.com:1883` must be reachable from your host. If you are behind a strict firewall, outbound TCP port 1883 must be open. Use `-v` to see all raw MQTT messages on the `GoMDP/#` topic.

---

## Security considerations

- Credentials are transmitted to the device **in plaintext** over TCP (the XOR "encryption" provides no real security).
- The MQTT broker is a public endpoint shared with other Slinex devices worldwide. The `notify` mode subscribes to all messages under `GoMDP/#` — use the UID filter (`-h <uid>`) to scope events to your device only.
- Run this tool only on a trusted local network segment.

---

## License

MIT
