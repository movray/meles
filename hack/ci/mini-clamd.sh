#!/bin/sh
# Writes a minimal clamd setup to <dir>: a database with only an EICAR hash
# signature and the chart's YARA rules, and a clamd.conf listening on TCP
# <port>. Enough for `meles selftest --yara` and the integration tests,
# without downloading the full database from Cisco Talos on every CI run.
#
#   hack/ci/mini-clamd.sh /tmp/clamd 3310
#   clamd --config-file=/tmp/clamd/clamd.conf
set -eu
dir=${1:?usage: mini-clamd.sh <dir> [port]}
port=${2:-3310}
here=$(cd "$(dirname "$0")/../.." && pwd)

mkdir -p "$dir/db"
# MD5 and size of the EICAR test file: a hash only, so this file does not
# trigger virus scanners itself.
echo '44d88612fea8a8f36de82e1278abb02f:68:Eicar-Test-Signature' > "$dir/db/eicar.hdb"
cp "$here"/charts/meles/rules/*.yar "$dir/db/"

# Limits as in the chart's defaults (scan.maxFileSize 768M).
cat > "$dir/clamd.conf" <<EOF
DatabaseDirectory $dir/db
TCPSocket $port
TCPAddr 0.0.0.0
Foreground yes
LogTime yes
StreamMaxLength 768M
MaxFileSize 768M
MaxScanSize 1024M
EOF
