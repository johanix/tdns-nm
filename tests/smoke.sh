#!/bin/bash
#
# Smoke test for tdns-kdc, tdns-krs, kdc-cli and krs-cli.
#
# Runs a KDC and a KRS on 127.0.0.1 from the binaries built in this tree
# (run "make" first), enrolls one node and exercises enrollment, ping,
# component assignment, key distribution, key deletion and the test text
# distributions, and checks that a KRS without the KDC's key refuses to start. Everything lives in a temporary directory; both daemons
# are stopped on exit.
#
# usage: tests/smoke.sh [workdir]
#   workdir                 empty directory to use (default: a new mktemp -d)
#   SMOKE_PORT_PREFIX=NN    ports NN354/NN355 (DNS) and NN991/NN990 (API); default 25
#   SMOKE_KEEP=1            keep the work directory after a passing run
#
# Exit status: 0 when every step passes or fails as known, 1 otherwise.

ROOT=$(cd "$(dirname "$0")/.." && pwd)
W=${1:-$(mktemp -d "${TMPDIR:-/tmp}/tdns-nm-smoke.XXXXXX")}
PFX=${SMOKE_PORT_PREFIX:-25}
KDCDNS=127.0.0.1:${PFX}354; KDCAPI=127.0.0.1:${PFX}991
KRSDNS=127.0.0.1:${PFX}355; KRSAPI=127.0.0.1:${PFX}990
KCLI="$ROOT/cmd/kdc-cli/kdc-cli --config $W/tdns-cli.yaml"
RCLI="$ROOT/cmd/krs-cli/krs-cli --config $W/krs/tdns-krs.yaml"
KDCLOG=$W/kdc/tdns-kdc.log; KRSLOG=$W/krs/tdns-krs.log
TEXT="smoke test text from the KDC to node1"

# Steps that fail today because of known bugs. A known step that passes is
# reported as XPASS: take it off this list.
#   roll-key:     the roll_key API generates a key it never stores, so the
#                 distribution record's foreign key fails
#   cli-setstate: kdc-cli zone setstate sends zone_id, the API wants zone_name
KNOWN_FAIL=" roll-key cli-setstate "

for b in tdns-kdc tdns-krs kdc-cli krs-cli; do
	if [ ! -x "$ROOT/cmd/$b/$b" ]; then
		echo "missing $ROOT/cmd/$b/$b: run make first" >&2
		exit 1
	fi
done
for t in openssl curl; do
	command -v $t > /dev/null || { echo "$t is required" >&2; exit 1; }
done

mkdir -p "$W/kdc" "$W/krs" "$W/certs" "$W/blobs" "$W/out"
RES=$W/results.txt
: > "$RES"
FAILED=0

cleanup() {
	pkill -f "tdns-kdc --config $W/kdc/tdns-kdc.yaml"
	pkill -f "tdns-krs --config $W/krs/tdns-krs.yaml"
}
trap cleanup EXIT

res() { # step PASS|"FAIL detail"
	local verdict=$2
	case "$KNOWN_FAIL" in
	*" $1 "*)
		case "$2" in
		PASS*) verdict="XPASS (fixed? take it off KNOWN_FAIL)" ;;
		*) verdict="XFAIL ${2#FAIL }" ;;
		esac ;;
	*)
		case "$2" in
		PASS*) ;;
		*) FAILED=1 ;;
		esac ;;
	esac
	printf '%-22s %s\n' "$1" "$verdict" | tee -a "$RES"
}
waitfor() { # file pattern seconds
	local i
	for ((i = 0; i < $3 * 4; i++)); do
		grep -q -F -- "$2" "$1" 2>/dev/null && return 0
		sleep 0.25
	done
	return 1
}
run() { # step cmd... ; output in $W/out/step
	local name=$1; shift
	(cd "$W" && "$@") > "$W/out/$name" 2>&1
}
lastline() { grep -v '^\s*$' "$W/out/$1" | tail -1 | cut -c1-110; }

echo "tdns-nm smoke test in $W"

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
	-keyout "$W/certs/localhost.key" -out "$W/certs/localhost.crt" -days 2 \
	-subj /CN=localhost -addext 'subjectAltName=IP:127.0.0.1' > /dev/null 2>&1

cat > "$W/tdns-cli.yaml" <<EOF
apiservers:
   - name:              tdns-kdc
     baseurl:           https://$KDCAPI/api/v1
     apikey:            smoke-kdc-api-key
     authmethod:        X-API-Key
     config:            $W/kdc/tdns-kdc.yaml
log:
   file:		$W/kdc-cli.log
EOF

# KDC key and daemon
run keygen $KCLI keys generate --jose-outfile "$W/kdc/kdc.jose.privatekey"
[ -f "$W/kdc/kdc.jose.privatekey" ] && res keys-generate PASS || res keys-generate "FAIL $(lastline keygen)"

cat > "$W/kdc/tdns-kdc.yaml" <<EOF
service:
   name:                TDNS-KDC
   verbose:             true
   debug:               false
apiserver:
   usetls:              true
   addresses:           [ $KDCAPI ]
   apikey:              smoke-kdc-api-key
   certfile:            $W/certs/localhost.crt
   keyfile:             $W/certs/localhost.key
listeners:
   addresses:           [ $KDCDNS ]
   transports:          [ do53 ]
kdc:
   database:
      type:               sqlite
      dsn:                "$W/kdc/kdc.db"
   control_zone:        "kdc.test."
   default_algorithm:    15
   key_rotation_interval: 720h
   standby_key_count:    1
   publish_time:         1m
   retire_time:          1h
   distribution_ttl:     5m
   chunk_max_size:   60000
   kdc_enrollment_address: $KDCDNS
   kdc_jose_priv_key: $W/kdc/kdc.jose.privatekey
log:
   file:                $KDCLOG
EOF
(cd "$W/kdc" && exec "$ROOT/cmd/tdns-kdc/tdns-kdc" --config "$W/kdc/tdns-kdc.yaml" > "$W/kdc/stdout.log" 2>&1) &
waitfor "$KDCLOG" "KDC started successfully" 20 && res kdc-start PASS || res kdc-start "FAIL $(tail -1 "$W/kdc/stdout.log" | cut -c1-110)"

# Enrollment
run enroll-gen $KCLI node enroll generate --nodeid node1.test. --outdir "$W/blobs"
[ -f "$W/blobs/node1.test.enroll" ] && res enroll-generate PASS || res enroll-generate "FAIL $(lastline enroll-gen)"
run enroll-act $KCLI node enroll activate --nodeid node1.test.
grep -q activated "$W/out/enroll-act" && res enroll-activate PASS || res enroll-activate "FAIL $(lastline enroll-act)"

run krs-enroll "$ROOT/cmd/krs-cli/krs-cli" enroll --package "$W/blobs/node1.test.enroll" --configdir "$W/krs" \
	--notify-address "$KRSDNS" --api-address "$KRSAPI" --db-path "$W/krs/krs.db" --log-file "$KRSLOG"
grep -q "Enrollment completed successfully" "$W/out/krs-enroll" && res krs-enroll PASS || res krs-enroll "FAIL $(lastline krs-enroll)"

(cd "$W/krs" && exec "$ROOT/cmd/tdns-krs/tdns-krs" --config "$W/krs/tdns-krs.yaml" > "$W/krs/stdout.log" 2>&1) &
waitfor "$KRSLOG" "KRS started successfully" 20 && res krs-start PASS || res krs-start "FAIL $(tail -1 "$W/krs/stdout.log" | cut -c1-110)"

# A KRS without the KDC's JOSE public key cannot verify a distribution: it must refuse to start
sed -e '/kdc_jose_pubkey:/d' -e "s#$W/krs/krs.db#$W/krs/nokey.db#" -e "s#$KRSLOG#$W/krs/nokey.log#" \
	"$W/krs/tdns-krs.yaml" > "$W/krs/nokey.yaml"
(cd "$W/krs" && exec "$ROOT/cmd/tdns-krs/tdns-krs" --config "$W/krs/nokey.yaml" > "$W/out/krs-nokey" 2>&1) &
NOKEY=$!
for ((i = 0; i < 40; i++)); do
	kill -0 $NOKEY 2>/dev/null || break
	sleep 0.25
done
if kill -0 $NOKEY 2>/dev/null; then
	kill $NOKEY
	res krs-needs-kdc-key "FAIL started without kdc_jose_pubkey"
elif grep -q "KDC verification key" "$W/out/krs-nokey"; then
	res krs-needs-kdc-key PASS
else
	res krs-needs-kdc-key "FAIL $(lastline krs-nokey)"
fi

# Ping
run ping $KCLI node ping --nodeid node1.test.
if waitfor "$KRSLOG" "Ping operation successful" 10 && waitfor "$KDCLOG" "Ping operation confirmed successfully" 10; then
	res ping PASS
else
	res ping "FAIL $(lastline ping)"
fi

# Service, component and zone
run svc-add $KCLI service add --sid edge --name Edge
run svc-comp $KCLI service component add --sname edge --cname sign_edge_zsk
run node-comp $KCLI node component add --nodeid node1.test. --cid sign_edge_zsk
waitfor "$KRSLOG" "Node component list updated" 10 && res node-components PASS || res node-components "FAIL $(lastline node-comp)"
run zone-add $KCLI zone add --zone z1.test. --sid edge
grep -q "added successfully" "$W/out/zone-add" && res zone-add PASS || res zone-add "FAIL $(lastline zone-add)"

# Keys: generate a ZSK and set it to standby through the API (the CLI
# setstate is a step of its own below)
newkey() { # step [zone] [type] -> echoes the key id
	run "$1" $KCLI zone dnssec generate --zone "${2:-z1.test.}" --type "${3:-ZSK}" --algorithm 15
	sed -n 's/^Key \([0-9]*\) generated successfully.*/\1/p' "$W/out/$1"
}
setstate() { # zone keyid state
	curl -sk -X POST -H 'X-API-Key: smoke-kdc-api-key' -H 'Content-Type: application/json' \
		-d "{\"command\":\"setstate\",\"zone_name\":\"$1\",\"key_id\":\"$2\",\"new_state\":\"$3\"}" \
		"https://$KDCAPI/api/v1/kdc/zone"
}
standby() { setstate z1.test. "$1" standby; }
KID=$(newkey keygen1)
[ -n "$KID" ] && res dnssec-generate "PASS (key $KID)" || res dnssec-generate "FAIL $(lastline keygen1)"
standby "$KID" > "$W/out/standby1"

run distrib-single $KCLI distrib single --zone z1.test. --keyid "$KID"
if waitfor "$KRSLOG" "Successfully stored ZSK (key_id $KID)" 10; then
	res distrib-single PASS
else
	res distrib-single "FAIL $(grep -o 'Error processing distribution.*' "$KRSLOG" | tail -1 | cut -c1-100)"
fi

run krs-list $RCLI dnssec list
grep -q "$KID" "$W/out/krs-list" && res krs-dnssec-list PASS || res krs-dnssec-list "FAIL $(lastline krs-list)"

KID2=$(newkey keygen2)
standby "$KID2" > "$W/out/standby2"
run distrib-multi $KCLI distrib multi z1.test.
waitfor "$KRSLOG" "Successfully stored ZSK (key_id $KID2)" 10 && res distrib-multi PASS || res distrib-multi "FAIL $(lastline distrib-multi)"

# edgesign_full: distrib single sends the zone's active KSK along with the ZSK
run svc-full $KCLI service add --sid full --name Full
run svc-full-comp $KCLI service component add --sname full --cname sign_edge_full
run node-full-comp $KCLI node component add --nodeid node1.test. --cid sign_edge_full
run zone-full $KCLI zone add --zone z2.test. --sid full
KSK=$(newkey keygen-ksk z2.test. KSK)
setstate z2.test. "$KSK" active > "$W/out/ksk-active"
ZSK2=$(newkey keygen-zsk2 z2.test. ZSK)
setstate z2.test. "$ZSK2" standby > "$W/out/zsk2-standby"
run distrib-full $KCLI distrib single --zone z2.test. --keyid "$ZSK2"
if waitfor "$KRSLOG" "Successfully stored ZSK (key_id $ZSK2)" 10 && waitfor "$KRSLOG" "Successfully stored KSK (key_id $KSK)" 10; then
	res distrib-single-full PASS
else
	res distrib-single-full "FAIL ZSK $ZSK2 / KSK $KSK not both stored"
fi

run delete-key $KCLI zone delete-key --zone z1.test. --keyid "$KID" --reason smoke
waitfor "$KRSLOG" "Successfully deleted key $KID" 10 && res delete-key PASS || res delete-key "FAIL $(lastline delete-key)"

run roll-key $KCLI zone roll-key --zone z1.test. --keytype ZSK
grep -q -i error "$W/out/roll-key" && res roll-key "FAIL $(lastline roll-key)" || res roll-key PASS

run setstate $KCLI zone setstate --zone z1.test. --keyid "$KID2" --state retired
grep -q -i error "$W/out/setstate" && res cli-setstate "FAIL $(lastline setstate)" || res cli-setstate PASS

# Test text distributions
printf '%s\n' "$TEXT" > "$W/text.txt"
for ct in clear_text encrypted_text; do
	id=$([ $ct = clear_text ] && echo c1a1 || echo e1e1)
	run gen-$ct $KCLI debug distrib generate --distid $id --nodeid node1.test. --file "$W/text.txt" --content-type $ct
	run fetch-$ct $RCLI debug distrib fetch --id $id
	grep -q -F "$TEXT" "$W/out/fetch-$ct" && res "text-$ct" PASS || res "text-$ct" "FAIL $(lastline fetch-$ct)"
done

# A payload too big for the manifest goes as data chunks, bound to the signed manifest by chunk_hash
awk 'BEGIN { for (i = 0; i < 3000; i++) printf "line %05d of the large smoke test text, padded out to make it long\n", i }' > "$W/large.txt"
run gen-large $KCLI debug distrib generate --distid 1a7e --nodeid node1.test. --file "$W/large.txt" --content-type clear_text
run fetch-large $RCLI debug distrib fetch --id 1a7e
if grep -q -F "line 02999 of the large smoke test text" "$W/out/fetch-large" && grep -q "Reassembled .* from [0-9]* CHUNK chunks" "$KRSLOG"; then
	res text-chunked "PASS ($(grep -o 'Reassembled .* CHUNK chunks' "$KRSLOG" | tail -1))"
else
	res text-chunked "FAIL $(lastline fetch-large)"
fi

# Listings
run node-list $KCLI node list
grep -q node1.test. "$W/out/node-list" && res kdc-node-list PASS || res kdc-node-list "FAIL $(lastline node-list)"
run zone-list $KCLI zone list
grep -q z1.test. "$W/out/zone-list" && res kdc-zone-list PASS || res kdc-zone-list "FAIL $(lastline zone-list)"
if run distrib-list $KCLI distrib list && ! grep -q -i error "$W/out/distrib-list"; then
	res kdc-distrib-list PASS
else
	res kdc-distrib-list "FAIL $(lastline distrib-list)"
fi
run krs-comp $RCLI components list
grep -q sign_edge_zsk "$W/out/krs-comp" && res krs-components-list PASS || res krs-components-list "FAIL $(lastline krs-comp)"
run krs-config $RCLI config get
grep -q node1.test. "$W/out/krs-config" && res krs-config-get PASS || res krs-config-get "FAIL $(lastline krs-config)"

if [ $FAILED -ne 0 ]; then
	echo "FAILED: logs and command output in $W"
	exit 1
fi
echo "PASSED"
[ -n "$SMOKE_KEEP" ] || [ -n "$1" ] || rm -rf "$W"
exit 0
