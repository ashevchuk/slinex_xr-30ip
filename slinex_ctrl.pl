#!/usr/bin/env perl

# slinex_ctrl.pl — Slinex intercom control via OWSP protocol
#
# Usage:
#   perl slinex_ctrl.pl [options] <command>
#
# Options:
#   -h <host>     Intercom IP address (required)
#   -p <port>     TCP port (default: 34567)
#   -u <user>     Username (default: admin)
#   -w <pass>     Login password (default: empty)
#   -l <lockpwd>  Lock password (default: = -w)
#   -c <ch>       Channel 0-7 (default: 0)
#   -d <sec>      Lock delay in seconds (default: 5)
#   -t <sec>      TCP timeout (default: 10)
#   -o            Use old login format (v3.7, 56 bytes)
#   -a            Enable audio in video mode
#   -e <cmd>      Command to run on doorbell call (notify mode)
#   -v            Verbose output (hex packet dumps)
#
# Commands:
#   unlock        Open the lock
#   lock          Close the lock
#   info          Device information
#   keepalive     Send a keepalive packet
#   video         Play camera video via mpv
#   intercom      Two-way audio intercom (arecord/aplay)
#   notify        Wait for doorbell call (TLV 341)

use strict;
use warnings;
use IO::Socket::INET;
use IO::Select;
use Getopt::Std;

# ─── Protocol constants ──────────────────────────────────────────────────────
use constant {
    TLV_VERSION_INFO     => 40,
    TLV_LOGIN_REQ        => 41,
    TLV_LOGIN_RSP        => 42,
    TLV_KEEPALIVE_REQ    => 49,
    TLV_KEEPALIVE_RSP    => 57,
    TLV_DEVICE_INFO_REQ  => 70,
    TLV_DEVICE_INFO_RSP  => 71,
    TLV_AUDIO_INFO       => 97,
    TLV_AUDIO_DATA       => 98,
    TLV_VIDEO_FRAME_INFO => 99,
    TLV_VIDEO_IFRAME     => 100,
    TLV_VIDEO_PFRAME     => 101,
    TLV_STREAM_FMT1      => 199,
    TLV_STREAM_FMT2      => 200,
    TLV_STREAM_FMT3      => 203,
    TLV_ALARM_REQ        => 341,
    TLV_ALARM_RSP        => 342,
    TLV_TALK_REQ         => 331,
    TLV_TALK_RSP         => 332,
    TLV_LOCK_REQ         => 425,
    TLV_LOCK_RSP         => 426,

    RESP_SUCC            => 1,
    LOCK_UNLOCK          => 1,
    LOCK_LOCK            => 0,
    ENCRYPT_KEY          => 'lbtech',

    SZ_OWSP      => 8,
    SZ_TLV       => 4,
    SZ_VER       => 4,
    SZ_LOGIN_OLD => 56,
    SZ_LOGIN_NEW => 68,
    SZ_LOCK_REQ  => 40,
};

my %RESP_STR = (
    1  => 'OK',
    2  => 'Wrong password',
    4  => 'Protocol version error',
    5  => 'Too many clients',
    6  => 'Device unavailable',
    8  => 'Device overloaded',
    9  => 'Invalid channel',
    10 => 'Protocol error',
    11 => 'Encoding not started',
    12 => 'Task execution error',
    13 => 'Configuration error',
    14 => 'Talk not supported',
    17 => 'Memory error',
    19 => 'User not found',
    22 => 'Insufficient privileges',
    35 => 'Access denied',
);

# ─── Encryption (Encrypt.EncrypKey) ──────────────────────────────────────────
# dest[i] = src[i] XOR (key[i % keylen] + 25)
sub encrypt_key {
    my ($text, $out_len) = @_;
    my @key = map { ord($_) } split //, ENCRYPT_KEY;
    my @src = map { ord($_) } split //, $text;
    my @out = (0) x $out_len;
    for my $i (0 .. $#src) {
        $out[$i] = ($src[$i] ^ ($key[$i % @key] + 25)) & 0xFF;
    }
    return @out;
}

# ─── G.711 μ-law codec (port of G711.java: G711_SUN_*) ──────────────────────
# seg_uend = {63, 127, 255, 511, 1023, 2047, 4095, 8191}
my @SEG_UEND = (63, 127, 255, 511, 1023, 2047, 4095, 8191);

# PCM s16 → G.711 μ-law byte (0..255)
sub g711_linear2ulaw {
    my ($pcm_val) = @_;
    $pcm_val = unpack('s', pack('s', $pcm_val));  # enforce signed 16-bit
    # Check sign BEFORE shift: Perl >> on negative numbers is undefined behavior.
    # Explicitly take the absolute value and set the sign mask.
    my ($v, $mask);
    if ($pcm_val < 0) {
        $v    = (-$pcm_val) >> 2;   # magnitude >> 2 (always non-negative)
        $mask = 0x7F;
    } else {
        $v    = $pcm_val >> 2;
        $mask = 0xFF;
    }
    $v = 8159 if $v > 8159;  # CLIP
    $v += 33;                # BIAS(132) >> 2 = 33
    my $seg = 8;
    for my $i (0 .. 7) {
        if ($v <= $SEG_UEND[$i]) { $seg = $i; last; }
    }
    return ($mask ^ 0x7F) & 0xFF if $seg >= 8;
    my $uval = ($seg << 4) | (($v >> ($seg + 1)) & 0xF);
    return ($uval ^ $mask) & 0xFF;
}

# PCM s16 → G.711 A-law byte (0..255)  (port of G711.java: s2a + alaw2ulaw via tables)
# Simplified direct implementation (no 64KB table required)
my @SEG_AEND = (31, 63, 127, 255, 511, 1023, 2047, 4095);
sub g711_linear2alaw {
    my ($pcm_val) = @_;
    $pcm_val = unpack('s', pack('s', $pcm_val));
    my ($v, $mask);
    if ($pcm_val >= 0) {
        $v    = $pcm_val >> 3;   # magnitude >> 3
        $mask = 0xD5;            # XOR mask for A-law (positive): 0x55 | 0x80
    } else {
        $v    = (-$pcm_val - 1) >> 3;
        $mask = 0x55;
    }
    $v = 4095 if $v > 4095;
    my $seg = 8;
    for my $i (0 .. 7) {
        if ($v <= $SEG_AEND[$i]) { $seg = $i; last; }
    }
    my $aval;
    if ($seg == 0) {
        $aval = ($v >> 1) & 0x0F;
    } else {
        $aval = (($seg << 4) | (($v >> $seg) & 0x0F));
    }
    return ($aval ^ $mask) & 0xFF;
}

# G.711 μ-law byte (0..255) → PCM s16
sub g711_ulaw2linear {
    my ($u_val) = @_;
    $u_val &= 0xFF;
    my $u_neg = $u_val ^ 0xFF;                   # ~u_val (8-bit)
    my $t     = (($u_neg & 0x0F) << 3) + 132;   # QUANT_MASK=15, BIAS=132
    my $shift = ($u_neg & 0x70) >> 4;            # SEG_MASK=112, SEG_SHIFT=4
    $t <<= $shift;
    return ($u_neg & 0x80) ? (132 - $t) : ($t - 132);  # SIGN_BIT=128
}

# ─── Header assembly ─────────────────────────────────────────────────────────
sub owsp { pack('NV', $_[0], $_[1]) }   # packet_length(BE) + seq(LE)
sub tlv  { pack('vv', $_[0], $_[1]) }   # type(LE) + len(LE)

# ─── Login packet — new format (v5.0, LoginRequestEx, 68 bytes) ──────────────
sub build_login_new {
    my ($user, $pass, $channel, $seq) = @_;
    $channel //= 0;

    my $ver_tlv  = tlv(TLV_VERSION_INFO, SZ_VER);
    my $ver_body = pack('vv', 5, 0);

    my @enc   = encrypt_key($pass, 16);
    my $uname = pack('a32', $user);
    my $pwd   = pack('C16', @enc);
    my $mask4 = pack('V', 1 << $channel);

    my $body = pack('C', 0) . $uname . $pwd
             . pack('V', 0)     # deviceId
             . pack('V', 0)     # flag
             . pack('a3', '')   # reserve3
             . $mask4           # channelMask (4 of 8 bytes from long2bytes)
             . pack('CCCC', 0, 0, 0, 0);  # streamMode, dataType, reserve x2

    die "LoginRequestEx size ".length($body)." != ".SZ_LOGIN_NEW."\n"
        if length($body) != SZ_LOGIN_NEW;

    my $login_tlv = tlv(TLV_LOGIN_REQ, SZ_LOGIN_NEW);
    my $payload   = $ver_tlv . $ver_body . $login_tlv . $body;
    return owsp(4 + length($payload), $seq) . $payload;
}

# ─── Login packet — old format (v3.7, LoginRequest, 56 bytes) ────────────────
sub build_login_old {
    my ($user, $pass, $channel, $device_id, $seq) = @_;
    $channel   //= 0;
    $device_id //= 1;

    my $ver_tlv  = tlv(TLV_VERSION_INFO, SZ_VER);
    my $ver_body = pack('vv', 3, 7);

    my @enc  = encrypt_key($pass, 16);
    my $body = pack('a32', $user)
             . pack('C16', @enc)
             . pack('V', $device_id)
             . pack('CC', 0, $channel)
             . pack('xx');

    die "LoginRequest size ".length($body)." != ".SZ_LOGIN_OLD."\n"
        if length($body) != SZ_LOGIN_OLD;

    my $login_tlv = tlv(TLV_LOGIN_REQ, SZ_LOGIN_OLD);
    my $payload   = $ver_tlv . $ver_body . $login_tlv . $body;
    return owsp(4 + length($payload), $seq) . $payload;
}

# ─── Keepalive ────────────────────────────────────────────────────────────────
sub build_keepalive {
    my ($seq) = @_;
    my $t = tlv(TLV_KEEPALIVE_REQ, 0);
    return owsp(4 + length($t), $seq) . $t;
}

# ─── Lock command ─────────────────────────────────────────────────────────────
sub build_lock {
    my ($lock_pwd, $channel, $action, $delay, $seq) = @_;
    $channel //= 0;  $delay //= 5;

    my @enc = encrypt_key($lock_pwd, 32);
    my $body = pack('V', 0)
             . pack('C32', @enc)
             . pack('CCCC', $channel, $action, $delay, 0);

    die "LockReq size ".length($body)." != ".SZ_LOCK_REQ."\n"
        if length($body) != SZ_LOCK_REQ;

    my $t = tlv(TLV_LOCK_REQ, SZ_LOCK_REQ);
    my $payload = $t . $body;
    return owsp(4 + length($payload), $seq) . $payload;
}

# ─── Stop Stream (TLV 47) ────────────────────────────────────────────────────
# TLV_V_StopStreamDataRequest: videoChannel(C) + audioChannel(C) + reserve(LE u16)
sub build_stop_stream {
    my ($video_ch, $audio_ch, $seq) = @_;
    $video_ch //= 0;  $audio_ch //= 0;
    my $body = pack('CCv', $video_ch, $audio_ch, 0);
    my $t    = tlv(47, length($body));
    return owsp(4 + length($t) + length($body), $seq) . $t . $body;
}

# ─── Talk Request (TLV 331, 28 bytes) ────────────────────────────────────────
# action: 1=start, 2=stop
sub build_talk_req {
    my ($action, $seq) = @_;
    my $body = pack('VCa3VVvvvvvv',
        0,              # deviceId
        $action,        # action
        "\x00\x00\x00", # reserve[3]
        8000,           # samplesPerSecond
        64000,          # audiobitrate
        31269,          # waveFormat = WAVE_FORMAT_G711U (μ-law, 0x7a25)
        1,              # channelNumber (mono)
        1,              # blockAlign
        8,              # bitsPerSample
        40,             # frameInterval (40 ms = 320 samples @ 8000 Hz)
        0,              # audioreserve
    );
    die "TalkReq size ".length($body)." != 28\n" if length($body) != 28;
    my $t = tlv(TLV_TALK_REQ, 28);
    return owsp(4 + length($t) + 28, $seq) . $t . $body;
}

# ─── Audio packet (TLV 97 + TLV 98 in one OWSP) ──────────────────────────────
# TLV_V_AudioInfoRequest: channelId(C)+reserve(C)+checksum(LE u16)+time(LE u32)
sub build_audio_packet {
    my ($ulaw_data, $channel_id, $seq) = @_;
    my $info = pack('CCvV',
        $channel_id,  # channelId = channel + 1
        0,            # reserve
        0,            # checksum
        200,          # time (hardcoded 200, as in Android app)
    );
    my $t97     = tlv(TLV_AUDIO_INFO, length($info));
    my $t98     = tlv(TLV_AUDIO_DATA, length($ulaw_data));
    my $payload = $t97 . $info . $t98 . $ulaw_data;
    return owsp(4 + length($payload), $seq) . $payload;
}

# ─── Device Info ─────────────────────────────────────────────────────────────
sub build_device_info {
    my ($seq) = @_;
    my $t = tlv(TLV_DEVICE_INFO_REQ, 0);
    return owsp(4 + length($t), $seq) . $t;
}

# ─── Reliable read of N bytes from socket ────────────────────────────────────
sub read_exactly {
    my ($sock, $n) = @_;
    my $buf = '';
    while (length($buf) < $n) {
        my $chunk = '';
        my $got = $sock->read($chunk, $n - length($buf));
        return undef unless defined $got && $got > 0;
        $buf .= $chunk;
    }
    return $buf;
}

# ─── Read one OWSP packet, all TLVs ──────────────────────────────────────────
# Returns arrayref of [type, body], undef on error
sub read_owsp_all_tlv {
    my ($sock) = @_;

    my $hdr = read_exactly($sock, SZ_OWSP);
    return undef unless defined $hdr;

    my ($pkt_len) = unpack('N', $hdr);
    my $payload_len = $pkt_len - 4;
    return [] if $payload_len <= 0;

    my $payload = read_exactly($sock, $payload_len);
    return undef unless defined $payload;

    # Parse all TLVs in payload
    my @tlvs;
    my $pos = 0;
    while ($pos + SZ_TLV <= length($payload)) {
        my ($type, $len) = unpack('vv', substr($payload, $pos, SZ_TLV));
        $pos += SZ_TLV;
        last if $pos + $len > length($payload);
        push @tlvs, [$type, substr($payload, $pos, $len)];
        $pos += $len;
    }
    return \@tlvs;
}

# ─── Read one packet (simple variant for lock/info) ──────────────────────────
sub read_packet {
    my ($sock, $verbose) = @_;
    my $tlvs = read_owsp_all_tlv($sock);
    return undef unless defined $tlvs && @$tlvs;
    my ($type, $body) = @{$tlvs->[0]};
    printf "    [TLV] type=%d len=%d\n", $type, length($body) if $verbose;
    printf "    [body] hex=%s\n", unpack('H*', $body) if $verbose && length($body) && length($body) <= 80;
    # Trailing TLVs — print if verbose
    if ($verbose && @$tlvs > 1) {
        printf "    [+%d TLV skipped]\n", scalar(@$tlvs) - 1;
    }
    return ($type, length($body), $body, $tlvs);
}

# ─── Read until the desired TLV type ─────────────────────────────────────────
# Returns ($type, $len, $body) of the desired TLV, or undef.
# Side-effect: captures TLV 40 (version) and TLV 70 (device info).
# If $capture_ref is provided — stores captured data into it as a hashref.
sub read_until {
    my ($sock, $want_type, $attempts, $verbose, $capture_ref) = @_;
    $attempts //= 8;
    for my $i (1 .. $attempts) {
        my $tlvs = read_owsp_all_tlv($sock);
        return undef unless defined $tlvs;
        for my $tlv (@$tlvs) {
            my ($type, $body) = @$tlv;
            if ($type == $want_type) {
                printf "  Received TLV %d\n", $want_type if $verbose;
                return ($type, length($body), $body);
            }
            printf "  Skipping TLV %d (expecting %d)\n", $type, $want_type if $verbose;
            if ($type == TLV_VERSION_INFO && length($body) >= 4) {
                my ($maj, $min) = unpack('vv', $body);
                printf "  [Device version: %d.%d]\n", $maj, $min;
                $capture_ref->{version} = "$maj.$min" if $capture_ref;
            }
            if ($type == TLV_DEVICE_INFO_REQ && $capture_ref) {
                $capture_ref->{device_info} = $body;
            }
        }
    }
    return undef;
}

# ─── Parse login response ─────────────────────────────────────────────────────
sub check_login_rsp {
    my ($body) = @_;
    return (0, "empty response") unless length($body) >= 2;
    my $result = unpack('v', substr($body, 0, 2));
    return ($result, $RESP_STR{$result} // "code $result");
}

# ─── Parse device info (TLV 70) ──────────────────────────────────────────────
# uid[16] + model[16] + hw[16] + build[16] + year(LE u16) + mon + day + h + m + s
sub print_device_info {
    my ($body) = @_;
    return unless length($body) >= 64;
    my ($uid, $model, $hw, $build) = unpack('a16a16a16a16', $body);
    s/\x00.*//s for ($uid, $model, $hw, $build);
    printf "  UID:        %s\n", $uid;
    printf "  Model:      %s\n", $model;
    printf "  Hardware:   %s\n", $hw;
    printf "  Firmware:   %s\n", $build;
    if (length($body) >= 71) {
        my ($year, $mon, $day, $hour, $min, $sec) =
            unpack('vCCCCC', substr($body, 64, 7));
        printf "  Date/Time:  %04d-%02d-%02d %02d:%02d:%02d\n",
            $year, $mon, $day, $hour, $min, $sec;
    }
}

# ─── Parse stream format (TLV 199/200/203) ───────────────────────────────────
# TLV_V_StreamDataFormat (40 bytes): all fields in little-endian
sub parse_stream_format {
    my ($body) = @_;
    return unless length($body) >= 40;

    my ($vch, $ach, $dtype, $res,
        $codec, $vbr, $w, $h,
        $fps, $cd, $vfi, $vr,
        $sps, $abr, $wf, $cn, $ba, $bps) =
        unpack('CCCCVVvvCCCCVVvvvv', substr($body, 0, 40));

    # codecId is stored as LE int, pack('V',...) gives ASCII: "H264" or "H265"
    my $codec_str = pack('V', $codec);
    $codec_str =~ s/[^\x20-\x7e]/./g;

    return ($codec_str, $w, $h, $fps, $sps, $cn);
}

# ─── Login with auto-fallback ─────────────────────────────────────────────────
# Returns ($result_code, $result_str, \%captured)
sub do_login {
    my ($sock, $user, $pass, $channel, $old_fmt, $verbose, $seq_ref) = @_;

    my $fmt_str = $old_fmt ? 'v3.7' : 'v5.0';
    printf "Login: user='%s' format=%s ...\n", $user, $fmt_str;

    my $pkt = $old_fmt
        ? build_login_old($user, $pass, $channel, 1, $$seq_ref++)
        : build_login_new($user, $pass, $channel, $$seq_ref++);

    printf "  Packet: %d bytes\n", length($pkt) if $verbose;
    print $sock $pkt;

    my %captured;
    my ($rtype, $rlen, $rbody) = read_until($sock, TLV_LOGIN_RSP, 8, $verbose, \%captured);
    return (0, "no login response", {}) unless defined $rtype;

    my ($code, $str) = check_login_rsp($rbody);
    return ($code, $str, \%captured);
}

# ─── Video mode ───────────────────────────────────────────────────────────────
sub cmd_video {
    my ($sock, $seq_ref, $channel, $with_audio, $verbose) = @_;

    # mpv command: reads H.264 Annex-B from stdin
    my @mpv = (
        'mpv',
        '--no-cache',
        '--demuxer=lavf',
        '--demuxer-lavf-format=h264',
        '--title=Slinex Door Camera',
        '--really-quiet',
    );
    push @mpv, '--no-audio' unless $with_audio;
    push @mpv, '-';

    printf "Starting: %s\n", join(' ', @mpv);
    open(my $mpv_fh, '|-', @mpv) or die "Failed to start mpv: $!\n";
    $mpv_fh->autoflush(1);

    local $SIG{PIPE} = sub { print "\nmpv finished.\n"; exit 0 };
    local $SIG{INT}  = sub { print "\nInterrupted.\n"; close($mpv_fh); exit 0 };

    my ($codec, $w, $h, $fps) = ('', 0, 0, 0);
    my $got_fmt     = 0;
    my $frame_count = 0;
    my $iframe_count = 0;

    print "Receiving video... (Ctrl+C to exit)\n";

    while (1) {
        my $tlvs = read_owsp_all_tlv($sock);
        last unless defined $tlvs;

        for my $tlv (@$tlvs) {
            my ($type, $body) = @$tlv;

            # Stream format information
            if ($type == TLV_STREAM_FMT1 || $type == TLV_STREAM_FMT2 || $type == TLV_STREAM_FMT3) {
                unless ($got_fmt) {
                    my ($cs, $cw, $ch2, $cfps, $sps, $cn) = parse_stream_format($body);
                    if (defined $cs) {
                        printf "Stream: %s %dx%d @%dfps  audio: %dHz %dch\n",
                            $cs, $cw, $ch2, $cfps, $sps, $cn;
                        ($codec, $w, $h, $fps) = ($cs, $cw, $ch2, $cfps);
                        $got_fmt = 1;
                    }
                }
            }

            # Video frames: TLV 100 (I-frame) and TLV 101 (P-frame)
            elsif ($type == TLV_VIDEO_IFRAME || $type == TLV_VIDEO_PFRAME) {
                next unless length($body) > 0;

                # Prepend Annex-B start code if data does not already start with it
                my $starts_with_sc =
                    length($body) >= 4 && substr($body, 0, 4) eq "\x00\x00\x00\x01";
                print $mpv_fh "\x00\x00\x00\x01" unless $starts_with_sc;
                print $mpv_fh $body;

                $frame_count++;
                $iframe_count++ if $type == TLV_VIDEO_IFRAME;

                if ($verbose && $frame_count % 30 == 0) {
                    printf "\r  frames: %d  I: %d  P: %d   ",
                        $frame_count, $iframe_count, $frame_count - $iframe_count;
                    STDOUT->flush;
                }

                # Keepalive every ~300 frames (~10s at 30fps)
                if ($frame_count % 300 == 0) {
                    print $sock build_keepalive($$seq_ref++);
                }
            }

            # TLV 97 (AUDIO_INFO), 98 (AUDIO_DATA), 99 (VIDEO_FRAME_INFO) — skip
        }
    }

    close($mpv_fh);
    printf "\nStream ended. Frames: %d (I=%d P=%d)\n",
        $frame_count, $iframe_count, $frame_count - $iframe_count;
}

# ─── Intercom mode (two-way audio) ───────────────────────────────────────────
sub cmd_intercom {
    my ($sock, $seq_ref, $channel, $verbose) = @_;

    # Stop video stream first — otherwise large I-frames block audio reception
    printf "  Stopping video stream...\n" if $verbose;
    print $sock build_stop_stream($channel, $channel, $$seq_ref++);
    # Temporary timeout to wait for TLV 48 (stop stream response)
    $sock->sockopt(SO_RCVTIMEO, pack('ll', 2, 0));
    read_until($sock, 48, 16, $verbose);
    $sock->sockopt(SO_RCVTIMEO, pack('ll', 0, 0));  # clear timeout

    # Request talk start (TLV 331, action=1)
    printf "Intercom request (TLV %d, action=1) ...\n", TLV_TALK_REQ;
    print $sock build_talk_req(1, $$seq_ref++);

    my ($rt, $rl, $rb) = read_until($sock, TLV_TALK_RSP, 16, $verbose);
    die "No response to TalkRequest\n" unless defined $rt;

    my $talk_wf = 31269;  # default: μ-law
    if (length($rb) >= 2) {
        my $result = unpack('v', substr($rb, 0, 2));
        if ($result != RESP_SUCC) {
            printf "Error: %s (code %d)\n", $RESP_STR{$result} // "code $result", $result;
            return;
        }
        # TalkResponse: result(v) + sampleRate(V) + bitrate(V) + waveFormat(v) + ...
        if (length($rb) >= 10) {
            my ($sps, $abr, $wf) = unpack('VVv', substr($rb, 2, 10));
            $talk_wf = $wf;
            printf "  Talk format: sampleRate=%d waveFormat=%d (0x%04x)\n", $sps, $wf, $wf;
        }
    }
    if ($talk_wf != 31269 && $talk_wf != 31257) {
        printf "Warning: unknown waveFormat=%d, trying μ-law\n", $talk_wf;
    }
    printf "  Codec: %s\n", ($talk_wf == 31257 ? 'G.711 A-law' : 'G.711 μ-law');
    print "Intercom active. Press Ctrl+C to stop.\n";

    # Pipe to aplay: PCM s16le 8000Hz mono; -B 500000 = 500ms buffer (jitter protection)
    my @aplay = ('aplay', '-q', '-B', '500000', '-r', '8000', '-f', 'S16_LE', '-c', '1', '-t', 'raw', '-');
    open(my $aplay_fh, '|-', @aplay) or die "Failed to start aplay: $!\n";
    $aplay_fh->autoflush(1);

    my $stop_talk = sub {
        print $sock build_talk_req(2, $$seq_ref++);
    };

    # Fork: child — write (mic → device), parent — read (device → speaker)
    my $pid = fork();
    die "fork: $!\n" unless defined $pid;

    if ($pid == 0) {
        # ─── Child process: mic → G.711 → device ─────────────────────────────
        local $SIG{INT}  = sub { exit 0 };
        local $SIG{TERM} = sub { exit 0 };

        my @arecord = ('arecord', '-q', '-r', '8000', '-f', 'S16_LE', '-c', '1', '-t', 'raw', '-');
        open(my $mic_fh, '-|', @arecord) or do { warn "arecord: $!\n"; exit 1 };
        binmode $mic_fh;

        my $child_seq  = 0;
        my $chan_id    = $channel + 1;
        my $use_alaw   = ($talk_wf == 31257) ? 1 : 0;  # 31257=A-law, 31269=μ-law
        while (1) {
            # Read 320 samples = 640 bytes PCM
            my $pcm = '';
            while (length($pcm) < 640) {
                my $chunk = '';
                my $got   = $mic_fh->read($chunk, 640 - length($pcm));
                last unless defined $got && $got > 0;
                $pcm .= $chunk;
            }
            last unless length($pcm) == 640;

            # Encode to G.711 (μ-law or A-law based on device response)
            my @samples = unpack('s<*', $pcm);
            my $enc = '';
            if ($use_alaw) {
                $enc .= chr(g711_linear2alaw($_)) for @samples;
            } else {
                $enc .= chr(g711_linear2ulaw($_)) for @samples;
            }

            print $sock build_audio_packet($enc, $chan_id, $child_seq++);
        }
        close $mic_fh;
        exit 0;
    }

    # ─── Parent process: device → G.711 → PCM → aplay ────────────────────────
    local $SIG{PIPE} = sub { print "\naplay finished.\n"; kill 'TERM', $pid; waitpid($pid,0); exit 0 };
    local $SIG{INT}  = sub {
        print "\nStopping intercom...\n";
        kill 'TERM', $pid;
        $stop_talk->();
        close $aplay_fh;
        waitpid($pid, 0);
        exit 0;
    };

    my $frame_count  = 0;
    my $audio_count  = 0;
    my $last_ka_time = time();

    while (1) {
        my $tlvs = read_owsp_all_tlv($sock);
        last unless defined $tlvs;

        for my $tlv_item (@$tlvs) {
            my ($type, $body) = @$tlv_item;

            if ($type == TLV_AUDIO_DATA && length($body) > 0) {
                # Decode G.711 μ-law → PCM s16le
                my $pcm = '';
                for my $i (0 .. length($body) - 1) {
                    $pcm .= pack('s<', g711_ulaw2linear(ord(substr($body, $i, 1))));
                }
                print $aplay_fh $pcm;
                $audio_count++;
                printf "\r  audio packets: %d  video frames: %d   ", $audio_count, $frame_count
                    if $verbose && $audio_count % 50 == 0;
            }
            elsif ($type == TLV_VIDEO_IFRAME || $type == TLV_VIDEO_PFRAME) {
                $frame_count++;
            }
        }

        # Keepalive every 10 seconds
        if (time() - $last_ka_time >= 10) {
            print $sock build_keepalive($$seq_ref++);
            $last_ka_time = time();
        }
    }

    kill 'TERM', $pid;
    $stop_talk->();
    close $aplay_fh;
    waitpid($pid, 0);
    printf "\nIntercom ended. Audio packets received: %d\n", $audio_count;
}

# ─── Call waiting mode ────────────────────────────────────────────────────────
# TLV_V_AlarmControl (8 bytes): deviceId(LE u32) + channel(C) + command(C) + mode(C) + reserve(C)
# Call notifications arrive via MQTT broker mobileeyedoor.push2u.com.
# Message format: companyId|deviceUid|...|[Ringing][timestamp]
# Pure-Perl MQTT 3.1.1 implementation — no external utilities needed.
sub cmd_notify {
    my ($uid_filter, $verbose, $on_event_cmd) = @_;

    my $broker    = 'mobileeyedoor.push2u.com';
    my $port      = 1883;
    my $topic     = 'GoMDP/#';
    my $client_id = 'slinex_' . $$;
    my $keepalive = 60;

    # MQTT remaining-length encoding (variable-length, up to 4 bytes)
    my $enc_len = sub {
        my ($n) = @_;
        my $r = '';
        do { my $b = $n & 0x7F; $n >>= 7; $b |= 0x80 if $n; $r .= chr($b) } while $n;
        $r;
    };

    printf "MQTT → %s:%d\n", $broker, $port;
    my $ms = IO::Socket::INET->new(
        PeerAddr => $broker, PeerPort => $port, Proto => 'tcp', Timeout => 10,
    ) or die "MQTT connect: $!\n";
    $ms->autoflush(1);

    # ── CONNECT ──────────────────────────────────────────────────────────────
    {
        my $vh = pack('n/a*', 'MQTT') . pack('CCn', 4, 0x02, $keepalive);
        my $pl = pack('n/a*', $client_id);
        print $ms "\x10" . $enc_len->(length($vh) + length($pl)) . $vh . $pl;
        my $ca = read_exactly($ms, 4) // die "No CONNACK\n";
        my $rc = ord(substr($ca, 3, 1));
        die "MQTT rejected (code $rc)\n" if $rc != 0;
    }

    # ── SUBSCRIBE ────────────────────────────────────────────────────────────
    {
        my $pl = pack('n/a*', $topic) . "\x00";   # topic + QoS 0
        print $ms "\x82" . $enc_len->(2 + length($pl)) . pack('n', 1) . $pl;
        read_exactly($ms, 5);  # SUBACK — ignored
    }

    printf "Subscribed to: %s\n", $topic;
    printf "UID filter: %s\n", $uid_filter if $uid_filter;
    print  "Waiting for call... (Ctrl+C to exit)\n";

    local $SIG{INT} = sub { $ms->close; print "\nMonitoring stopped.\n"; exit 0 };

    my $sel       = IO::Select->new($ms);
    my $last_ping = time();
    my $event_cnt = 0;

    while (1) {
        # PINGREQ every (keepalive-5) seconds
        if (time() - $last_ping >= $keepalive - 5) {
            print $ms "\xc0\x00";
            $last_ping = time();
            printf "  [PINGREQ]\n" if $verbose;
        }

        next unless $sel->can_read(10);

        # Read fixed-header byte
        my $fh = read_exactly($ms, 1) // last;
        my $pt = ord($fh) >> 4;

        # Decode remaining length
        my ($rem, $mult, $ok) = (0, 1, 1);
        for (1 .. 4) {
            my $b = read_exactly($ms, 1); unless (defined $b) { $ok = 0; last }
            $b = ord($b);
            $rem += ($b & 0x7F) * $mult;
            last unless $b & 0x80;
            $mult *= 128;
        }
        next unless $ok;

        my $data = $rem ? (read_exactly($ms, $rem) // next) : '';

        if ($pt == 3) {        # PUBLISH
            my $tlen      = unpack('n', substr($data, 0, 2));
            my $pub_topic = substr($data, 2, $tlen);
            my $msg       = substr($data, 2 + $tlen);

            printf "  MQTT [%s]: %s\n", $pub_topic, $msg if $verbose;

            next unless $msg =~ /\[Ringing\]/i;

            my @p  = split(/\|/, $msg);
            my $uid = $p[1] // '?';
            next if $uid_filter && $uid ne $uid_filter;

            $event_cnt++;
            my $raw_ts = $p[4] // '';
            my $ts = $raw_ts =~ /^\d{8}(\d{2})(\d{2})(\d{2})$/ ? "$1:$2:$3"
                   : do { my @t = localtime; sprintf "%02d:%02d:%02d", @t[2,1,0] };

            printf "[%s] *** CALL #%d  UID=%s ***\n", $ts, $event_cnt, $uid;

            if ($on_event_cmd) {
                my $pid = fork();
                if (defined $pid && $pid == 0) { exec $on_event_cmd; exit 127 }
            }

        } elsif ($pt == 13) {  # PINGRESP
            $last_ping = time();
            printf "  [PINGRESP]\n" if $verbose;
        }
    }
    $ms->close;
}

# ─── Usage/Help ──────────────────────────────────────────────────────────────
sub usage {
    print <<'USAGE';
Usage: perl slinex_ctrl.pl [options] <command>

Options:
  -h <host>    Intercom IP address (required)
  -p <port>    TCP port (default: 34567)
  -u <user>    Username (default: admin)
  -w <pass>    Password (default: empty)
  -l <pwd>     Lock password (default: = -w)
  -c <ch>      Channel 0-7 (default: 0)
  -d <sec>     Lock delay in seconds (default: 5)
  -t <sec>     TCP timeout (default: 10)
  -o           Old login format (v3.7, 56 bytes)
  -a           Enable audio in video mode
  -e <cmd>     Command to run on doorbell call (notify mode)
  -v           Verbose output

Commands:
  unlock       Open the lock
  lock         Close the lock
  info         Device information
  keepalive    Send keepalive (no login required)
  video        Play video via mpv
  intercom     Two-way audio intercom (arecord/aplay)
  notify       Wait for call (MQTT); -h <uid> — filter by device UID; -e <cmd> — command on ring
USAGE
    exit 1;
}

# ─── main ────────────────────────────────────────────────────────────────────
my %opts;
getopts('h:p:u:w:l:c:d:t:e:oav', \%opts) or usage();

my $host      = $opts{h} // '';
my $port      = $opts{p} || 34567;
my $user      = $opts{u} || 'admin';
my $pass      = $opts{w} // '';
my $lock_pwd  = $opts{l} // $pass;
my $channel   = $opts{c} //  0;
my $delay     = $opts{d} //  5;
my $timeout   = $opts{t} || 10;
my $old_fmt   = $opts{o} ? 1 : 0;
my $with_audio   = $opts{a} ? 1 : 0;
my $on_event_cmd = $opts{e} // '';
my $verbose      = $opts{v} ? 1 : 0;
my $cmd          = $ARGV[0] or do { print "Error: no command specified\n\n"; usage() };

usage() unless $cmd =~ /^(unlock|lock|info|keepalive|video|intercom|notify)$/;

# notify does not require an OWSP connection — works via MQTT
# -h is used as device UID filter (optional)
if ($cmd eq 'notify') {
    cmd_notify($host, $verbose, $on_event_cmd);
    exit 0;
}

$host or do { print "Error: host not specified (-h)\n\n"; usage() };

# ─── Connection ───────────────────────────────────────────────────────────────
printf "Connecting to %s:%d ...\n", $host, $port;
my $sock = IO::Socket::INET->new(
    PeerAddr => $host,
    PeerPort => $port,
    Proto    => 'tcp',
    Timeout  => $timeout,
) or die "Connection error: $!\n";
$sock->autoflush(1);
# Timeout only for non-streaming commands (video/intercom read indefinitely)
$sock->sockopt(SO_RCVTIMEO, pack('ll', $timeout, 0)) if $cmd ne 'video' && $cmd ne 'intercom';
print "Connected.\n";

my $seq = 0;

# ─── Keepalive without login ──────────────────────────────────────────────────
if ($cmd eq 'keepalive') {
    my $pkt = build_keepalive($seq++);
    printf "Sending keepalive (%d bytes) ...\n", length($pkt);
    print $sock $pkt;
    my ($r) = read_packet($sock, $verbose);
    if (defined $r && $r == TLV_KEEPALIVE_RSP) {
        print "Response received. Device is online.\n";
    } elsif (defined $r) {
        printf "Received TLV %d (expected %d).\n", $r, TLV_KEEPALIVE_RSP;
    } else {
        print "No response (device unavailable).\n";
    }
    $sock->close;
    exit 0;
}

# ─── Login ────────────────────────────────────────────────────────────────────
my ($result, $result_str, $captured) = do_login($sock, $user, $pass, $channel, $old_fmt, $verbose, \$seq);

if ($result != RESP_SUCC && !$old_fmt) {
    printf "Login (v5.0) failed: %s. Trying v3.7...\n", $result_str;
    $sock->close;
    printf "Reconnecting to %s:%d ...\n", $host, $port;
    $sock = IO::Socket::INET->new(
        PeerAddr => $host,
        PeerPort => $port,
        Proto    => 'tcp',
        Timeout  => $timeout,
    ) or die "Reconnection error: $!\n";
    $sock->autoflush(1);
    $sock->sockopt(SO_RCVTIMEO, pack('ll', $timeout, 0)) if $cmd ne 'video' && $cmd ne 'intercom';
    $seq = 0;
    ($result, $result_str, $captured) = do_login($sock, $user, $pass, $channel, 1, $verbose, \$seq);
}

die "Authentication error: $result_str\n" if $result != RESP_SUCC;
print "Logged in.\n";

# ─── For control commands: stop video stream ──────────────────────────────────
if ($cmd ne 'video' && $cmd ne 'intercom') {
    printf "  Stopping stream...\n" if $verbose;
    print $sock build_stop_stream($channel, $channel, $seq++);
    read_until($sock, 48, 5, $verbose);  # wait for TLV 48, not critical
}

# ─── Commands ─────────────────────────────────────────────────────────────────
if ($cmd eq 'video') {
    cmd_video($sock, \$seq, $channel, $with_audio, $verbose);

} elsif ($cmd eq 'intercom') {
    cmd_intercom($sock, \$seq, $channel, $verbose);

} elsif ($cmd eq 'unlock' || $cmd eq 'lock') {
    my $action  = ($cmd eq 'unlock') ? LOCK_UNLOCK : LOCK_LOCK;
    my $act_str = ($cmd eq 'unlock') ? 'unlock' : 'lock';
    printf "Lock command: %s (channel=%d, delay=%d s) ...\n",
        $act_str, $channel, $delay;

    my $pkt = build_lock($lock_pwd, $channel, $action, $delay, $seq++);
    printf "  Packet: %d bytes\n", length($pkt) if $verbose;
    printf "  Hex: %s\n", unpack('H*', $pkt)  if $verbose;
    print $sock $pkt;

    my ($rt, $rl, $rb) = read_until($sock, TLV_LOCK_RSP, 16, $verbose);
    die "Error: no response to lock command\n" unless defined $rt;

    my $res = length($rb) >= 2 ? unpack('v', substr($rb, 0, 2)) : 0;
    if ($res == RESP_SUCC) {
        printf "Done: %s.\n", $act_str;
    } else {
        printf "Lock error: %s (code %d)\n", $RESP_STR{$res} // '?', $res;
    }

} elsif ($cmd eq 'info') {
    # TLV 70 is sent automatically by the device on login — use it
    if (my $di = $captured->{device_info}) {
        print "Device information (from login):\n";
        print_device_info($di);
    } else {
        # Request explicitly as a fallback
        print "Requesting device info ...\n";
        print $sock build_device_info($seq++);
        my ($rt, $rl, $rb) = read_until($sock, TLV_DEVICE_INFO_RSP, 8, $verbose);
        if (defined $rt) {
            print_device_info($rb);
        } else {
            print "No response to info request.\n";
        }
    }
}

$sock->close;
print "Done.\n" if $cmd ne 'video';
