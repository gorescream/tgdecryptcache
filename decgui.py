import hashlib as h, os, cryptg, argparse, io, math
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms as algo, modes
import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk

THUMB_SIZE = (150, 150)
COLUMNS = 5
PAGE_SIZE = 100

parser = argparse.ArgumentParser(description='telega cache')
parser.add_argument('-p', nargs=2, metavar=('KEY', 'DATA'), help='Пути к ключам и дате')
parser.add_argument('-u', type=str, metavar='USERNAME', help='Имя юзера Windows')
args = parser.parse_args()

if args.u:
    k_path = f'C:/Users/{args.u}/AppData/Roaming/Telegram Desktop/tdata/key_datas'
    d_path = f'C:/Users/{args.u}/AppData/Roaming/Telegram Desktop/tdata/user_data'
elif args.p:
    k_path, d_path = args.p[0], args.p[1]
else:
    print("Open with -p <key_datas file> <user_data folder> or -u <username>")
    exit()

with open(k_path, 'rb') as f: d = f.read()
s_len = int.from_bytes(d[8:12], 'big')
salt, p = d[12 : 12 + s_len], 16 + s_len
enc_k = d[p : p + int.from_bytes(d[p-4 : p], 'big')]
pk = h.pbkdf2_hmac("sha512", h.sha512(salt * 2).digest(), salt, 1, 256)
ek = enc_k[:16]
a, b, c = h.sha1(ek + pk[8:40]).digest(), h.sha1(pk[40:56] + ek + pk[56:72]).digest(), h.sha1(pk[72:104] + ek).digest()
dec = cryptg.decrypt_ige(enc_k[16:], a[:8] + b[8:20] + c[4:16], a[8:20] + b[:8] + c[16:20] + h.sha1(ek + pk[104:136]).digest()[:8])
key = dec[4 : int.from_bytes(dec[:4], 'little')]
half = len(key) // 2

root = tk.Tk()
root.title("tg cache")
root.geometry("850x750")

images_metadata = [] 
print("Reading cache")

for r, _, files in os.walk(d_path):
    for n in files:
        if n in ('version', 'binlog'): continue
        try:
            with open(os.path.join(r, n), 'rb') as f:
                if f.read(4) != b'TDEF': continue 
                s = f.read(64)
                data = Cipher(algo.AES(h.sha256(key[:half] + s[:32]).digest()), modes.CTR(h.sha256(key[half:] + s[32:]).digest()[:16])).decryptor().update(f.read())[48:]
                if not data: continue
                
                ext = None
                if data[:3] == b'\xFF\xD8\xFF': ext = '.jpg'
                elif data[:4] == b'\x89PNG': ext = '.png'
                elif data[:3] == b'GIF': ext = '.gif'
                elif data[:4] == b'RIFF': ext = '.webp'
                
                if ext:
                    images_metadata.append((n, ext, data))
        except: pass

if not images_metadata:
    print("Not found!")
    root.destroy()
    exit()

total_pages = math.ceil(len(images_metadata) / PAGE_SIZE)
current_page = 0
current_tk_images = []
nav_frame = tk.Frame(root, bg="#ddd", pady=5)
nav_frame.pack(side="top", fill="x")

lbl_page = tk.Label(nav_frame, text=f"Page 1 | {total_pages} (All: {len(images_metadata)})", bg="#ddd", font=("Arial", 10, "bold"))
lbl_page.pack(side="top", pady=5)

canvas = tk.Canvas(root, borderwidth=0, background="#f0f0f0")
frame = tk.Frame(canvas, background="#f0f0f0")
vsb = tk.Scrollbar(root, orient="vertical", command=canvas.yview)
canvas.configure(yscrollcommand=vsb.set)

vsb.pack(side="right", fill="y")
canvas.pack(side="left", fill="both", expand=True)
canvas_frame = canvas.create_window((0,0), window=frame, anchor="nw")

def on_frame_configure(event): canvas.configure(scrollregion=canvas.bbox("all"))
frame.bind("<Configure>", on_frame_configure)
def on_canvas_configure(event): canvas.itemconfig(canvas_frame, width=event.width)
canvas.bind('<Configure>', on_canvas_configure)
def _on_mousewheel(event): canvas.yview_scroll(int(-1*(event.delta/120)), "units")
canvas.bind_all("<MouseWheel>", _on_mousewheel)

def open_viewer(name, ext, full_bytes):
    viewer = tk.Toplevel(root)
    viewer.title(f"Watch: {name}")
    
    pil_img = Image.open(io.BytesIO(full_bytes))
    screen_w, screen_h = root.winfo_screenwidth(), root.winfo_screenheight()
    pil_img.thumbnail((screen_w - 100, screen_h - 200))
    
    tk_photo = ImageTk.PhotoImage(pil_img)
    img_label = tk.Label(viewer, image=tk_photo)
    img_label.image = tk_photo 
    img_label.pack(padx=10, pady=10, expand=True, fill=tk.BOTH)
    
    def save_this():
        fpath = filedialog.asksaveasfilename(defaultextension=ext, initialfile=name + ext, title="Сохранить как...")
        if fpath:
            with open(fpath, 'wb') as f: f.write(full_bytes)
            messagebox.showinfo("ОК", "Saved!")

    tk.Button(viewer, text="Save", command=save_this, font=("Arial", 11)).pack(pady=10)

def draw_page(page_idx):
    global current_tk_images
    current_tk_images.clear()
    
    for widget in frame.winfo_children():
        widget.destroy()
        
    start_idx = page_idx * PAGE_SIZE
    end_idx = start_idx + PAGE_SIZE
    page_items = images_metadata[start_idx:end_idx]
    
    row, col = 0, 0
    for name, ext, data in page_items:
        pil_img = Image.open(io.BytesIO(data))
        pil_img.thumbnail(THUMB_SIZE)
        bg = Image.new('RGB', THUMB_SIZE, (240, 240, 240)) 
        img_w, img_h = pil_img.size
        bg.paste(pil_img, ((THUMB_SIZE[0] - img_w) // 2, (THUMB_SIZE[1] - img_h) // 2))
        
        tk_thumb = ImageTk.PhotoImage(bg)
        current_tk_images.append(tk_thumb)
        
        btn = tk.Button(frame, image=tk_thumb, command=lambda n=name, e=ext, d=data: open_viewer(n, e, d), borderwidth=1, relief="flat", bg="white")
        btn.grid(row=row, column=col, padx=5, pady=5)
        
        col += 1
        if col >= COLUMNS:
            col, row = 0, row + 1
            
    lbl_page.config(text=f"Page {page_idx + 1} | {total_pages} (All: {len(images_metadata)})")
    root.update_idletasks()
    canvas.yview_moveto(0)

def prev_page():
    global current_page
    if current_page > 0:
        current_page -= 1
        draw_page(current_page)

def next_page():
    global current_page
    if current_page < total_pages - 1:
        current_page += 1
        draw_page(current_page)

btn_prev = tk.Button(nav_frame, text="<- Back", command=prev_page, font=("Arial", 10), width=15)
btn_prev.pack(side="left", padx=20)
btn_next = tk.Button(nav_frame, text="Next ->", command=next_page, font=("Arial", 10), width=15)
btn_next.pack(side="right", padx=20)

draw_page(0)

print("Done.")
root.mainloop()