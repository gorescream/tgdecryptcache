import hashlib as h, os, cryptg, argparse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms as algo, modes

parser = argparse.ArgumentParser()
parser.add_argument('-p', nargs=2, metavar=('KEY_PATH', 'DATA_PATH'))
parser.add_argument('-u', type=str, metavar='USERNAME')
args = parser.parse_args()

if args.u:
    k_path = f'C:/Users/{args.u}/AppData/Roaming/Telegram Desktop/tdata/key_datas'
    d_path = f'C:/Users/{args.u}/AppData/Roaming/Telegram Desktop/tdata/user_data'
elif args.p:
    k_path, d_path = args.p[0], args.p[1]
else:
    print("use: -p [full path] (key_data files and user_data folder) or -u [username]")
    exit()

with open(k_path, 'rb') as f: d = f.read()

s_len = int.from_bytes(d[8:12], 'big')
salt, p = d[12 : 12 + s_len], 16 + s_len
enc_k = d[p : p + int.from_bytes(d[p-4 : p], 'big')]

pk = h.pbkdf2_hmac("sha512", h.sha512(salt * 2).digest(), salt, 1, 256)
ek = enc_k[:16]

a, b, c = h.sha1(ek + pk[8:40]).digest(), h.sha1(pk[40:56] + ek + pk[56:72]).digest(), h.sha1(pk[72:104] + ek).digest()

dec = cryptg.decrypt_ige(
    enc_k[16:], 
    a[:8] + b[8:20] + c[4:16], 
    a[8:20] + b[:8] + c[16:20] + h.sha1(ek + pk[104:136]).digest()[:8]
)

key = dec[4 : int.from_bytes(dec[:4], 'little')]
half = len(key) // 2

for r, _, files in os.walk(d_path):
    for n in files:
        if n in ('version', 'binlog'): continue
        try:
            with open(os.path.join(r, n), 'rb') as f:
                if f.read(4) != b'TDEF': continue 
                s = f.read(64)
                
                data = Cipher(
                    algo.AES(h.sha256(key[:half] + s[:32]).digest()), 
                    modes.CTR(h.sha256(key[half:] + s[32:]).digest()[:16])
                ).decryptor().update(f.read())[48:]
                
                if not data: continue
                
                ext = '.jpg' if data[:3] == b'\xFF\xD8\xFF' else '.png' if data[:4] == b'\x89PNG' else '.ogg' if data[:4] == b'OggS' else '.mp4' if data[4:8] == b'ftyp' else '.tgs' if data[:3] == b'\x1F\x8B\x08' else '.zip' if data[:2] == b'PK' else '.gif' if data[:3] == b'GIF' else '.webp' if data[:4] == b'RIFF' else '.bin'
                
                out_dir = r.replace(d_path, '').strip('\\/')
                os.makedirs(out_dir, exist_ok=True)
                with open(os.path.join(out_dir, n + ext), 'wb') as out: out.write(data)
                print(f'{n} -> {ext}')
        except: pass