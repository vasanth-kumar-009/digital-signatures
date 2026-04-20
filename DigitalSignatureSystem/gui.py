import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import os
import copy
from keygen import generate_rsa_keys, generate_ecdsa_keys
from sign import sign_file
from verify import verify_file, tamper_and_verify
from compare import run_comparison
from utils import get_file_info, read_logs

# Configuration
THEME = {
    "header_bg": "#1e1e2e",
    "header_fg": "#ffffff",
    "btn_blue": "#4361ee",
    "btn_hover": "#3b55d9",
    "btn_success": "#2dc653",
    "btn_fail": "#ef233c",
    "btn_orange": "#f77f00",
    "btn_orange_hover": "#d66e00",
    "bg_light": "#f4f4f4",
    "tab_bg": "#ffffff",
    "text": "#333333",
    "font_main": ("Segoe UI", 10),
    "font_title": ("Segoe UI", 16, "bold"),
    "font_header": ("Segoe UI", 12, "bold")
}

class HoverButton(tk.Button):
    def __init__(self, master, hover_bg=THEME["btn_hover"], normal_bg=THEME["btn_blue"], **kw):
        tk.Button.__init__(self, master=master, **kw)
        self.default_bg = normal_bg
        self.hover_bg = hover_bg
        self.configure(bg=self.default_bg, fg='white', font=THEME["font_main"], 
                       relief=tk.FLAT, activebackground=self.hover_bg, activeforeground='white',
                       cursor="hand2", padx=10, pady=5)
        self.bind("<Enter>", self.on_enter)
        self.bind("<Leave>", self.on_leave)

    def on_enter(self, e):
        self['background'] = self.hover_bg

    def on_leave(self, e):
        self['background'] = self.default_bg

class DigitalSignatureApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Digital Signature System")
        self.root.geometry("900x700")
        self.root.configure(bg=THEME["bg_light"])
        
        # Style configuration
        self.style = ttk.Style()
        self.style.theme_use('default')
        self.style.configure("TNotebook", background=THEME["bg_light"], borderwidth=0)
        self.style.configure("TNotebook.Tab", font=THEME["font_main"], padding=[10, 5], background="#e0e0e0")
        self.style.map("TNotebook.Tab", background=[("selected", THEME["tab_bg"])])
        self.style.configure("TFrame", background=THEME["tab_bg"])
        self.style.configure("Light.TFrame", background=THEME["bg_light"])
        
        self.create_header()
        self.create_tabs()

    def create_header(self):
        header = tk.Frame(self.root, bg=THEME["header_bg"], height=60)
        header.pack(fill=tk.X, side=tk.TOP)
        header.pack_propagate(False)
        
        lbl = tk.Label(header, text="Digital Signature System", bg=THEME["header_bg"], 
                       fg=THEME["header_fg"], font=THEME["font_title"])
        lbl.pack(side=tk.LEFT, padx=20, pady=15)

    def create_tabs(self):
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Tab 1: Generate Keys
        self.tab_keys = ttk.Frame(notebook)
        notebook.add(self.tab_keys, text="1. Generate Keys")
        self.build_keygen_tab()
        
        # Tab 2: Sign File
        self.tab_sign = ttk.Frame(notebook)
        notebook.add(self.tab_sign, text="2. Sign File")
        self.build_sign_tab()
        
        # Tab 3: Verify File
        self.tab_verify = ttk.Frame(notebook)
        notebook.add(self.tab_verify, text="3. Verify File")
        self.build_verify_tab()
        
        # Tab 4: Compare RSA/ECDSA
        self.tab_compare = ttk.Frame(notebook)
        notebook.add(self.tab_compare, text="4. Performance")
        self.build_compare_tab()
        
        # Tab 5: Audit Log
        self.tab_log = ttk.Frame(notebook)
        notebook.add(self.tab_log, text="5. Audit Log")
        self.build_log_tab()
        
        # Bind tab change event to refresh log
        notebook.bind("<<NotebookTabChanged>>", self.on_tab_change)

    def on_tab_change(self, event):
        tab = event.widget.tab('current')['text']
        if "Audit Log" in tab:
            self.refresh_logs()

    def create_file_browser(self, parent, label_text, row, param_var, filetypes=None):
        tk.Label(parent, text=label_text, bg=THEME["tab_bg"], font=THEME["font_main"]).grid(row=row, column=0, sticky=tk.W, pady=10, padx=10)
        entry = tk.Entry(parent, textvariable=param_var, font=THEME["font_main"], width=50)
        entry.grid(row=row, column=1, padx=10, pady=10)
        
        def browse():
            filepath = filedialog.askopenfilename(filetypes=filetypes or [("All Files", "*.*")])
            if filepath:
                param_var.set(filepath)
                if hasattr(self, 'on_file_selected') and label_text == "File to Sign:":
                    self.on_file_selected(filepath)
                    
        btn = HoverButton(parent, text="Browse", command=browse)
        btn.grid(row=row, column=2, padx=10, pady=10)
        return entry

    # --- Tab 1: Generate Keys ---
    def build_keygen_tab(self):
        frame = ttk.Frame(self.tab_keys, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)

        tk.Label(frame, text="Generate Cryptographic Keys", bg=THEME["tab_bg"], font=THEME["font_header"]).grid(row=0, column=0, columnspan=2, sticky=tk.W, pady=(0, 20))

        self.algo_var = tk.StringVar(value="RSA")
        tk.Label(frame, text="Algorithm:", bg=THEME["tab_bg"], font=THEME["font_main"]).grid(row=1, column=0, sticky=tk.W, pady=5)
        
        algo_frame = tk.Frame(frame, bg=THEME["tab_bg"])
        algo_frame.grid(row=1, column=1, sticky=tk.W, pady=5)
        tk.Radiobutton(algo_frame, text="RSA", variable=self.algo_var, value="RSA", bg=THEME["tab_bg"], command=self.toggle_key_size).pack(side=tk.LEFT)
        tk.Radiobutton(algo_frame, text="ECDSA (SECP256R1)", variable=self.algo_var, value="ECDSA", bg=THEME["tab_bg"], command=self.toggle_key_size).pack(side=tk.LEFT, padx=10)

        self.rsa_size_var = tk.IntVar(value=2048)
        self.size_frame = tk.Frame(frame, bg=THEME["tab_bg"])
        self.size_frame.grid(row=2, column=1, sticky=tk.W, pady=5)
        tk.Label(self.size_frame, text="RSA Key Size:", bg=THEME["tab_bg"], font=THEME["font_main"]).pack(side=tk.LEFT)
        tk.Radiobutton(self.size_frame, text="1024-bit", variable=self.rsa_size_var, value=1024, bg=THEME["tab_bg"]).pack(side=tk.LEFT, padx=5)
        tk.Radiobutton(self.size_frame, text="2048-bit", variable=self.rsa_size_var, value=2048, bg=THEME["tab_bg"]).pack(side=tk.LEFT, padx=5)
        tk.Radiobutton(self.size_frame, text="4096-bit", variable=self.rsa_size_var, value=4096, bg=THEME["tab_bg"]).pack(side=tk.LEFT, padx=5)

        tk.Label(frame, text="Password (Optional):", bg=THEME["tab_bg"], font=THEME["font_main"]).grid(row=3, column=0, sticky=tk.W, pady=15)
        self.pass_var = tk.StringVar()
        tk.Entry(frame, textvariable=self.pass_var, show="*", font=THEME["font_main"], width=30).grid(row=3, column=1, sticky=tk.W, pady=15)

        HoverButton(frame, text="Generate Keys", command=self.do_keygen).grid(row=4, column=0, columnspan=2, pady=20)
        
        ttk.Separator(frame, orient='horizontal').grid(row=5, column=0, columnspan=3, sticky="ew", pady=10)

        self.lbl_key_res = tk.Label(frame, text="", bg=THEME["tab_bg"], font=THEME["font_main"], fg=THEME["text"], justify=tk.LEFT)
        self.lbl_key_res.grid(row=6, column=0, columnspan=3, sticky=tk.W, pady=10)

    def toggle_key_size(self):
        if self.algo_var.get() == "RSA":
            self.size_frame.grid()
        else:
            self.size_frame.grid_remove()

    def do_keygen(self):
        algo = self.algo_var.get()
        pwd = self.pass_var.get() or None
        try:
            if algo == "RSA":
                priv, pub = generate_rsa_keys(password=pwd, key_size=self.rsa_size_var.get())
            else:
                priv, pub = generate_ecdsa_keys(password=pwd)
                
            pwd_status = "Protected with password" if pwd else "No password protection"
            self.lbl_key_res.config(text=f"Success! [{algo}]\nPrivate key saved to: {priv}\nPublic key saved to: {pub}\n{pwd_status}", fg=THEME["btn_success"])
        except Exception as e:
            self.lbl_key_res.config(text=f"Error generating keys: {str(e)}", fg=THEME["btn_fail"])

    # --- Tab 2: Sign File ---
    def build_sign_tab(self):
        frame = ttk.Frame(self.tab_sign, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)

        tk.Label(frame, text="Sign a Document", bg=THEME["tab_bg"], font=THEME["font_header"]).grid(row=0, column=0, columnspan=3, sticky=tk.W, pady=(0, 20))

        self.sign_file_var = tk.StringVar()
        self.create_file_browser(frame, "File to Sign:", 1, self.sign_file_var)

        self.file_info_lbl = tk.Label(frame, text="", bg=THEME["tab_bg"], font=("Segoe UI", 9, "italic"), fg="#666666")
        self.file_info_lbl.grid(row=2, column=1, sticky=tk.W, pady=(0, 10))

        self.sign_key_var = tk.StringVar()
        self.create_file_browser(frame, "Private Key (.pem):", 3, self.sign_key_var, [("PEM Files", "*.pem")])

        tk.Label(frame, text="Signer Name:", bg=THEME["tab_bg"], font=THEME["font_main"]).grid(row=4, column=0, sticky=tk.W, pady=10, padx=10)
        self.signer_var = tk.StringVar(value="Admin")
        tk.Entry(frame, textvariable=self.signer_var, font=THEME["font_main"], width=30).grid(row=4, column=1, sticky=tk.W, pady=10, padx=10)

        tk.Label(frame, text="Algorithm:", bg=THEME["tab_bg"], font=THEME["font_main"]).grid(row=5, column=0, sticky=tk.W, pady=10, padx=10)
        self.sign_algo_var = tk.StringVar(value="RSA")
        algo_frame = tk.Frame(frame, bg=THEME["tab_bg"])
        algo_frame.grid(row=5, column=1, sticky=tk.W, padx=10)
        tk.Radiobutton(algo_frame, text="RSA", variable=self.sign_algo_var, value="RSA", bg=THEME["tab_bg"]).pack(side=tk.LEFT)
        tk.Radiobutton(algo_frame, text="ECDSA", variable=self.sign_algo_var, value="ECDSA", bg=THEME["tab_bg"]).pack(side=tk.LEFT, padx=10)

        tk.Label(frame, text="Password (if any):", bg=THEME["tab_bg"], font=THEME["font_main"]).grid(row=6, column=0, sticky=tk.W, pady=10, padx=10)
        self.sign_pwd_var = tk.StringVar()
        tk.Entry(frame, textvariable=self.sign_pwd_var, show="*", font=THEME["font_main"], width=30).grid(row=6, column=1, sticky=tk.W, pady=10, padx=10)

        HoverButton(frame, text="Sign File", command=self.do_sign).grid(row=7, column=1, sticky=tk.W, pady=20, padx=10)

        ttk.Separator(frame, orient='horizontal').grid(row=8, column=0, columnspan=3, sticky="ew", pady=10)
        
        self.lbl_sign_res = tk.Label(frame, text="", bg=THEME["tab_bg"], font=THEME["font_main"], fg=THEME["text"], justify=tk.LEFT)
        self.lbl_sign_res.grid(row=9, column=0, columnspan=3, sticky=tk.W, padx=10)

    def on_file_selected(self, filepath):
        info = get_file_info(filepath)
        if info:
            self.file_info_lbl.config(text=f"Selected: {info['name']} | Size: {info['size']} | Type: {info['type']}")

    def do_sign(self):
        fpath = self.sign_file_var.get()
        kpath = self.sign_key_var.get()
        algo = self.sign_algo_var.get()
        pwd = self.sign_pwd_var.get() or None
        signer = self.signer_var.get()
        
        if not fpath or not kpath:
            messagebox.showerror("Error", "Please select both a file and a private key.")
            return

        try:
            sig_path, f_hash = sign_file(fpath, kpath, algorithm=algo, password=pwd, signer_name=signer)
            res_text = f"Signed successfully!\nSignature saved to: {sig_path}\nAlgorithm: {algo} | Signer: {signer}\nFile Hash: {f_hash[:20]}..."
            self.lbl_sign_res.config(text=res_text, fg=THEME["btn_success"])
        except Exception as e:
            self.lbl_sign_res.config(text=f"Signing failed: {str(e)}", fg=THEME["btn_fail"])

    # --- Tab 3: Verify File ---
    def build_verify_tab(self):
        frame = ttk.Frame(self.tab_verify, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)

        tk.Label(frame, text="Verify Document Authenticity", bg=THEME["tab_bg"], font=THEME["font_header"]).grid(row=0, column=0, columnspan=3, sticky=tk.W, pady=(0, 20))

        self.ver_file_var = tk.StringVar()
        self.create_file_browser(frame, "Original File:", 1, self.ver_file_var)

        self.ver_sig_var = tk.StringVar()
        self.create_file_browser(frame, "Signature File (.sig):", 2, self.ver_sig_var, [("Signature Files", "*.sig")])

        self.ver_key_var = tk.StringVar()
        self.create_file_browser(frame, "Public Key (.pem):", 3, self.ver_key_var, [("PEM Files", "*.pem")])

        btn_frame = tk.Frame(frame, bg=THEME["tab_bg"])
        btn_frame.grid(row=4, column=1, sticky=tk.W, pady=20, padx=10)
        HoverButton(btn_frame, text="Verify", command=lambda: self.do_verify(tamper=False)).pack(side=tk.LEFT)
        HoverButton(btn_frame, text="Tamper + Verify Demo", normal_bg=THEME["btn_orange"], hover_bg=THEME["btn_orange_hover"], command=lambda: self.do_verify(tamper=True)).pack(side=tk.LEFT, padx=10)

        ttk.Separator(frame, orient='horizontal').grid(row=5, column=0, columnspan=3, sticky="ew", pady=10)

        # Result display area
        self.lbl_ver_status = tk.Label(frame, text="", bg=THEME["tab_bg"], font=("Segoe UI", 14, "bold"))
        self.lbl_ver_status.grid(row=6, column=0, columnspan=3, pady=10)

        self.txt_ver_details = tk.Text(frame, height=8, width=70, font=("Consolas", 9), bg=THEME["bg_light"], state=tk.DISABLED)
        self.txt_ver_details.grid(row=7, column=0, columnspan=3, padx=10, pady=5)

    def do_verify(self, tamper):
        fpath = self.ver_file_var.get()
        spath = self.ver_sig_var.get()
        kpath = self.ver_key_var.get()

        if not all([fpath, spath, kpath]):
            messagebox.showerror("Error", "Please select file, signature, and public key.")
            return

        self.lbl_ver_status.config(text="Verifying...", fg=THEME["text"])
        self.root.update()

        try:
            if tamper:
                result = tamper_and_verify(fpath, spath, kpath)
            else:
                result = verify_file(fpath, spath, kpath)

            if result["valid"]:
                self.lbl_ver_status.config(text="✔ SIGNATURE VALID", fg=THEME["btn_success"])
            else:
                self.lbl_ver_status.config(text=f"✖ SIGNATURE INVALID: {result['message']}", fg=THEME["btn_fail"])

            # Show details
            details = result.get("details", {})
            d_text = f"Signer: {details.get('signer', 'N/A')}\n"
            d_text += f"Algorithm: {details.get('algorithm', 'N/A')}\n"
            d_text += f"Signed On: {details.get('signed_on', 'N/A')}\n"
            d_text += f"Original Hash: {details.get('original_hash', 'N/A')}\n"
            d_text += f"Current Hash:  {details.get('current_hash', 'N/A')}\n"
            d_text += f"Hash Matches: {details.get('hash_match', 'N/A')}\n"
            
            if tamper:
                d_text += "\n[DEMO NOTE: The original file was NOT modified. A temporary tampered copy was verified.]"

            self.txt_ver_details.config(state=tk.NORMAL)
            self.txt_ver_details.delete("1.0", tk.END)
            self.txt_ver_details.insert(tk.END, d_text)
            self.txt_ver_details.config(state=tk.DISABLED)

        except Exception as e:
            self.lbl_ver_status.config(text="Error during verification", fg=THEME["btn_fail"])
            self.txt_ver_details.config(state=tk.NORMAL)
            self.txt_ver_details.delete("1.0", tk.END)
            self.txt_ver_details.insert(tk.END, str(e))
            self.txt_ver_details.config(state=tk.DISABLED)


    # --- Tab 4: RSA vs ECDSA Comparison ---
    def build_compare_tab(self):
        frame = ttk.Frame(self.tab_compare, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)

        tk.Label(frame, text="Algorithm Performance Comparison", bg=THEME["tab_bg"], font=THEME["font_header"]).grid(row=0, column=0, columnspan=3, sticky=tk.W, pady=(0, 20))

        self.comp_file_var = tk.StringVar()
        self.create_file_browser(frame, "Test File:", 1, self.comp_file_var)

        self.btn_compare = HoverButton(frame, text="Run Benchmarks", command=self.start_comparison)
        self.btn_compare.grid(row=2, column=1, sticky=tk.W, pady=10, padx=10)

        # Table setup
        cols = ("Metric", "RSA (2048-bit)", "ECDSA (SECP256R1)")
        self.tree = ttk.Treeview(frame, columns=cols, show='headings', height=7)
        for col in cols:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=200, anchor=tk.CENTER)
            
        # Add alternating row colors tag
        self.tree.tag_configure('oddrow', background="#f9f9f9")
        self.tree.tag_configure('evenrow', background="#ffffff")
        
        self.tree.grid(row=3, column=0, columnspan=3, pady=20, padx=10)

        note = "Note: ECDSA offers smaller key sizes and faster key generation/signing for the\nsame security level, though RSA verification is typically faster."
        tk.Label(frame, text=note, bg=THEME["tab_bg"], font=("Segoe UI", 9, "italic"), fg="#555555", justify=tk.LEFT).grid(row=4, column=0, columnspan=3, sticky=tk.W, padx=10)

    def start_comparison(self):
        fpath = self.comp_file_var.get()
        if not fpath:
            messagebox.showerror("Error", "Please select a test file first.")
            return

        self.btn_compare.config(state=tk.DISABLED, text="Running...")
        # Clear tree
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        threading.Thread(target=self.run_compare_thread, args=(fpath,), daemon=True).start()

    def run_compare_thread(self, fpath):
        try:
            metrics = run_comparison(fpath)
            self.root.after(0, self.update_compare_ui, metrics)
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"Comparison failed: {str(e)}"))
            self.root.after(0, lambda: self.btn_compare.config(state=tk.NORMAL, text="Run Benchmarks"))

    def update_compare_ui(self, m):
        self.btn_compare.config(state=tk.NORMAL, text="Run Benchmarks")
        
        data = [
            ("Key Generation Time", f"{m['RSA']['keygen_ms']:.2f} ms", f"{m['ECDSA']['keygen_ms']:.2f} ms"),
            ("Sign Time", f"{m['RSA']['sign_ms']:.2f} ms", f"{m['ECDSA']['sign_ms']:.2f} ms"),
            ("Verify Time", f"{m['RSA']['verify_ms']:.2f} ms", f"{m['ECDSA']['verify_ms']:.2f} ms"),
            ("Private Key Size", f"{m['RSA']['priv_key_size']} bytes", f"{m['ECDSA']['priv_key_size']} bytes"),
            ("Public Key Size", f"{m['RSA']['pub_key_size']} bytes", f"{m['ECDSA']['pub_key_size']} bytes"),
            ("Signature Size", f"{m['RSA']['sig_size']} bytes", f"{m['ECDSA']['sig_size']} bytes"),
        ]
        
        for i, row in enumerate(data):
            tag = 'evenrow' if i % 2 == 0 else 'oddrow'
            self.tree.insert("", tk.END, values=row, tags=(tag,))


    # --- Tab 5: Audit Log ---
    def build_log_tab(self):
        frame = ttk.Frame(self.tab_log, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)

        header_frame = tk.Frame(frame, bg=THEME["tab_bg"])
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(header_frame, text="System Audit Log", bg=THEME["tab_bg"], font=THEME["font_header"]).pack(side=tk.LEFT)
        HoverButton(header_frame, text="Refresh Logs", command=self.refresh_logs).pack(side=tk.RIGHT)

        # Scrollable text area
        self.txt_log = tk.Text(frame, font=("Consolas", 10), bg="#1e1e2e", fg="#00ff00", insertbackground="white")
        scrollbar = ttk.Scrollbar(frame, command=self.txt_log.yview)
        self.txt_log.configure(yscrollcommand=scrollbar.set)
        
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.txt_log.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    def refresh_logs(self):
        self.txt_log.config(state=tk.NORMAL)
        self.txt_log.delete("1.0", tk.END)
        
        logs = read_logs()
        # Show newest first
        for entry in reversed(logs):
            ts = entry.get("timestamp", "").split(".")[0].replace("T", " ")
            action = entry.get("action", "")
            file = entry.get("filename", "")
            res = entry.get("result", "")
            ext = entry.get("extra", "")
            
            log_line = f"[{ts}] {action} | File: {file} | Status: {res} | {ext}\n"
            self.txt_log.insert(tk.END, log_line)
            
        self.txt_log.config(state=tk.DISABLED)


if __name__ == "__main__":
    root = tk.Tk()
    app = DigitalSignatureApp(root)
    root.mainloop()
