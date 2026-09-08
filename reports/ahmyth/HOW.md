# Ahmyth family rule report — how to rerun

Facts recorded from one quark run. No accuracy claim.

## Pinned values

- Sample URL: `https://github.com/quark-engine/apk-samples/raw/master/malware-samples/Ahmyth.apk`
- Sample SHA256: `f39b1a25c299ff532df840c6216fee41c8eb70787aba5e51624aae7b8eccc12c`
- quark-engine: `26.9.1` (PyPI), core library `dextrace` (CLI default)
- Rules repo used by freshquark: `https://github.com/quark-engine/quark-rules`
- Rules commit: `a9fb558fae4c9d23f325289396c06d7c5e519318`
- Rules directory passed to quark: the `rules/` directory from that commit (`quark.config.DIR_PATH` is `$HOME/.quark-engine/quark-rules/rules` after freshquark)
- Hit rule: a crime in the quark JSON whose `confidence` is `100%`
- Hit count: 42 (see `ahmyth-report.json`)

## Exact rerun command

Do not commit the APK. Download it to a temp path and check the SHA256 before analyzing.

```bash
pip install 'quark-engine==26.9.1'

# freshquark clones https://github.com/quark-engine/quark-rules into
# $HOME/.quark-engine/quark-rules and serves rules from
# $HOME/.quark-engine/quark-rules/rules.
# Pin the commit actually used (do not float on latest):
#   git -C "$HOME/.quark-engine/quark-rules" checkout a9fb558fae4c9d23f325289396c06d7c5e519318
# This prep run did not clone. It used the commit archive instead:

SAMPLE_URL='https://github.com/quark-engine/apk-samples/raw/master/malware-samples/Ahmyth.apk'
RULES_COMMIT=a9fb558fae4c9d23f325289396c06d7c5e519318
TMPDIR=$(mktemp -d)
curl -fsSL -o "$TMPDIR/Ahmyth.apk" "$SAMPLE_URL"
echo "f39b1a25c299ff532df840c6216fee41c8eb70787aba5e51624aae7b8eccc12c  $TMPDIR/Ahmyth.apk" | sha256sum -c -
curl -fsSL -o "$TMPDIR/quark-rules.zip" \
  "https://github.com/quark-engine/quark-rules/archive/${RULES_COMMIT}.zip"
unzip -q "$TMPDIR/quark-rules.zip" -d "$TMPDIR"
quark -a "$TMPDIR/Ahmyth.apk" \
  -r "$TMPDIR/quark-rules-${RULES_COMMIT}/rules" \
  -o "$TMPDIR/report.json" \
  --core-library dextrace
```

Command recorded in the JSON:

```text
quark -a Ahmyth.apk -r quark-rules-a9fb558fae4c9d23f325289396c06d7c5e519318/rules -o report.json --core-library dextrace
```

`ahmyth-summary.md` is generated from `ahmyth-report.json` (rule id, label list, crime text). The draft checker is `check_ahmyth_report.py`.
