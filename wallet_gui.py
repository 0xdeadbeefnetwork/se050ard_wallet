#!/usr/bin/env python3
"""
SE050ARD Hardware Bitcoin Wallet - GUI
======================================

Tkinter GUI for the SE050 hardware wallet.
Designed to work over VNC.

Features:
- Wallet creation with BIP39 seed phrase
- Lazy mode: skip verification, copy seed to clipboard 🦥
- Import existing seed phrases
- Balance display with USD conversion
- Send transactions with fee estimation
- Message signing
- Transaction history
- SE050 verification

Usage:
    ./wallet_gui.py
    ./wallet_gui.py --testnet

Author: _SiCk @ afflicted.sh
License: MIT
"""

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import threading
import sys
import os

# Import wallet functions
from wallet import (
    Config, Wallet,
    se050_connect, se050_disconnect, se050_reconnect,
    se050_key_exists, se050_sign, se050_get_uid, se050_get_random,
    se050_generate_keypair, se050_export_pubkey, se050_delete_key,
    se050_set_ecc_keypair,
    get_utxos, get_address_info, get_fee_estimates, get_btc_price, get_address_txs,
    format_timestamp, build_and_sign_transaction, create_output_script, api_post,
    sign_message_with_se050, encode_signed_message,
    generate_qr_ascii, hash160, sha256, parse_amount,
    generate_mnemonic, validate_mnemonic, mnemonic_to_seed,
    derive_bip84_key, compress_pubkey, derive_addresses
)

# Try to get backend info
try:
    from se050_interface import get_backend, is_native_available
    SE050_BACKEND = get_backend()
except ImportError:
    SE050_BACKEND = "ssscli"
    def is_native_available():
        return False

from datetime import datetime
from pathlib import Path

# Try to import QR code libraries for graphical QR
try:
    import qrcode
    from PIL import Image, ImageTk
    HAS_QR = True
except ImportError:
    HAS_QR = False


class WalletGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SE050ARD Bitcoin Wallet")
        self.root.geometry("900x700")
        self.root.configure(bg='#0f0f1a')
        self.root.minsize(800, 600)
        
        # Wallet state
        self.wallet = Wallet()
        self.connected = False
        self.balance_sats = 0
        self.btc_price = None
        self.monitoring = False
        self.monitor_interval = 30  # seconds
        self.last_balance = 0
        
        # Style
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.configure_styles()
        
        # Build UI with tabs
        self.create_widgets()
        
        # Initial load
        self.root.after(100, self.initial_load)
    
    def configure_styles(self):
        """Configure ttk styles for polished dark theme"""
        # Colors
        self.bg_dark = '#0f0f1a'
        self.bg_mid = '#1a1a2e'
        self.bg_light = '#252540'
        self.fg_main = '#e8e8e8'
        self.fg_dim = '#888899'
        self.accent = '#f39c12'
        self.accent_green = '#27ae60'
        self.accent_red = '#e74c3c'
        self.accent_blue = '#3498db'
        
        # Frame styles
        self.style.configure('TFrame', background=self.bg_dark)
        self.style.configure('Card.TFrame', background=self.bg_mid)
        
        # Label styles
        self.style.configure('TLabel', background=self.bg_dark, foreground=self.fg_main, font=('Segoe UI', 10))
        self.style.configure('Title.TLabel', font=('Segoe UI', 16, 'bold'), foreground=self.accent, background=self.bg_dark)
        self.style.configure('Subtitle.TLabel', font=('Segoe UI', 11, 'bold'), foreground=self.fg_main, background=self.bg_dark)
        self.style.configure('Balance.TLabel', font=('Segoe UI', 28, 'bold'), foreground=self.accent_green, background=self.bg_dark)
        self.style.configure('Address.TLabel', font=('Consolas', 9), foreground=self.accent_blue, background=self.bg_dark)
        self.style.configure('Status.TLabel', font=('Segoe UI', 9), foreground=self.fg_dim, background=self.bg_dark)
        self.style.configure('Card.TLabel', background=self.bg_mid, foreground=self.fg_main, font=('Segoe UI', 10))
        
        # Button styles
        self.style.configure('TButton', font=('Segoe UI', 10), padding=(15, 8))
        self.style.map('TButton',
            background=[('active', self.bg_light), ('!active', self.bg_mid)],
            foreground=[('active', self.fg_main), ('!active', self.fg_main)])
        
        self.style.configure('Accent.TButton', font=('Segoe UI', 10, 'bold'), padding=(15, 8))
        
        # Entry styles  
        self.style.configure('TEntry', fieldbackground=self.bg_light, foreground=self.fg_main)
        
        # Notebook (tabs)
        self.style.configure('TNotebook', background=self.bg_dark, borderwidth=0)
        self.style.configure('TNotebook.Tab', font=('Segoe UI', 10, 'bold'), padding=(20, 10),
                            background=self.bg_mid, foreground=self.fg_dim)
        self.style.map('TNotebook.Tab',
            background=[('selected', self.bg_light)],
            foreground=[('selected', self.accent)])
        
        # Treeview
        self.style.configure('Treeview', 
            background=self.bg_mid, 
            foreground=self.fg_main, 
            fieldbackground=self.bg_mid,
            font=('Consolas', 9),
            rowheight=28)
        self.style.configure('Treeview.Heading', 
            background=self.bg_light, 
            foreground=self.fg_main,
            font=('Segoe UI', 9, 'bold'))
        self.style.map('Treeview', background=[('selected', self.bg_light)])
        
        # LabelFrame
        self.style.configure('TLabelframe', background=self.bg_dark)
        self.style.configure('TLabelframe.Label', background=self.bg_dark, foreground=self.accent, font=('Segoe UI', 10, 'bold'))
        
        # Combobox
        self.style.configure('TCombobox', fieldbackground=self.bg_light, background=self.bg_mid)
        
        # Scrollbar
        self.style.configure('TScrollbar', background=self.bg_mid, troughcolor=self.bg_dark)
        
    def create_widgets(self):
        """Create all UI widgets with tabs"""
        # Main container
        self.main_frame = ttk.Frame(self.root, padding=15)
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Header
        header_frame = ttk.Frame(self.main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 15))
        
        ttk.Label(header_frame, text="SE050ARD WALLET", style='Title.TLabel').pack(side=tk.LEFT)
        
        # Network badge
        network_color = self.accent_red if Config.NETWORK == 'mainnet' else self.accent
        network_text = f"● {Config.NETWORK.upper()}"
        self.network_label = ttk.Label(header_frame, text=network_text, foreground=network_color, font=('Segoe UI', 10, 'bold'))
        self.network_label.pack(side=tk.RIGHT)
        
        # Connection status
        self.status_frame = ttk.Frame(self.main_frame)
        self.status_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.status_indicator = tk.Canvas(self.status_frame, width=10, height=10, bg=self.bg_dark, highlightthickness=0)
        self.status_indicator.pack(side=tk.LEFT, padx=(0, 8))
        self.status_dot = self.status_indicator.create_oval(1, 1, 9, 9, fill='#666', outline='')
        
        self.status_label = ttk.Label(self.status_frame, text="Connecting...", style='Status.TLabel')
        self.status_label.pack(side=tk.LEFT)
        
        # Notebook (tabs)
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        
        # Tab 1: Wallet
        self.wallet_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.wallet_tab, text='💰 Wallet')
        self.create_wallet_tab()
        
        # Tab 2: History
        self.history_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.history_tab, text='📜 History')
        self.create_history_tab()
        
        # Tab 3: Keys
        self.keys_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.keys_tab, text='🔐 Keys')
        self.create_keys_tab()
        
        # Bottom status bar
        self.bottom_status = ttk.Label(self.main_frame, text="", style='Status.TLabel')
        self.bottom_status.pack(fill=tk.X, pady=(10, 0))
    
    def create_wallet_tab(self):
        """Create the main wallet tab"""
        frame = self.wallet_tab
        frame.configure(style='TFrame')
        
        # Add padding frame
        content = ttk.Frame(frame)
        content.pack(fill=tk.BOTH, expand=True, padx=20, pady=15)
        
        # === BALANCE SECTION ===
        self.balance_label = tk.Label(content, text="0", font=('Segoe UI', 42, 'bold'), 
                                       fg='#2ecc71', bg=self.bg_dark)
        self.balance_label.pack(anchor=tk.W)
        
        self.fiat_label = tk.Label(content, text="sats", font=('Segoe UI', 14), 
                                    fg='#888', bg=self.bg_dark)
        self.fiat_label.pack(anchor=tk.W, pady=(0, 25))
        
        # === ADDRESS SECTION ===
        addr_container = tk.Frame(content, bg=self.bg_mid, padx=15, pady=15)
        addr_container.pack(fill=tk.X, pady=(0, 20))
        
        # SegWit
        tk.Label(addr_container, text="RECEIVE ADDRESS (SegWit)", font=('Segoe UI', 9, 'bold'),
                 fg='#888', bg=self.bg_mid).pack(anchor=tk.W)
        
        segwit_frame = tk.Frame(addr_container, bg=self.bg_mid)
        segwit_frame.pack(fill=tk.X, pady=(5, 10))
        
        self.segwit_var = tk.StringVar(value="---")
        self.segwit_entry = tk.Entry(segwit_frame, textvariable=self.segwit_var, 
                                      font=('Consolas', 11), bg=self.bg_light, fg='#3498db',
                                      relief=tk.FLAT, state='readonly', readonlybackground=self.bg_light)
        self.segwit_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=8)
        
        copy_segwit_btn = tk.Button(segwit_frame, text="Copy", font=('Segoe UI', 9),
                                     bg=self.bg_light, fg='#fff', relief=tk.FLAT,
                                     activebackground='#3498db', padx=15, pady=6,
                                     command=self.copy_segwit)
        copy_segwit_btn.pack(side=tk.RIGHT, padx=(10, 0))
        
        # Legacy (smaller, less prominent)
        tk.Label(addr_container, text="Legacy", font=('Segoe UI', 8),
                 fg='#666', bg=self.bg_mid).pack(anchor=tk.W)
        
        self.legacy_var = tk.StringVar(value="---")
        legacy_frame = tk.Frame(addr_container, bg=self.bg_mid)
        legacy_frame.pack(fill=tk.X, pady=(2, 0))
        
        self.legacy_entry = tk.Entry(legacy_frame, textvariable=self.legacy_var,
                                      font=('Consolas', 9), bg=self.bg_mid, fg='#666',
                                      relief=tk.FLAT, state='readonly', readonlybackground=self.bg_mid)
        self.legacy_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        copy_legacy_btn = tk.Button(legacy_frame, text="Copy", font=('Segoe UI', 8),
                                     bg=self.bg_mid, fg='#666', relief=tk.FLAT,
                                     activebackground='#555', padx=10,
                                     command=self.copy_legacy)
        copy_legacy_btn.pack(side=tk.RIGHT)
        
        # === QR CODE ===
        qr_frame = tk.Frame(addr_container, bg=self.bg_mid)
        qr_frame.pack(pady=(15, 0))
        
        self.qr_canvas = tk.Canvas(qr_frame, width=150, height=150, bg='white', 
                                    highlightthickness=0)
        self.qr_canvas.pack()
        self.qr_canvas.create_text(75, 75, text="QR", fill='#ccc', font=('Segoe UI', 12))
        
        # === ACTION BUTTONS ===
        btn_frame = tk.Frame(content, bg=self.bg_dark)
        btn_frame.pack(fill=tk.X, pady=(10, 0))
        
        buttons = [
            ("Send", self.show_send_dialog, '#e74c3c'),
            ("Sign", self.show_sign_dialog, '#9b59b6'),
            ("Refresh", self.refresh_balance, '#3498db'),
            ("Verify", self.verify_se050, '#27ae60'),
        ]
        
        for text, cmd, color in buttons:
            btn = tk.Button(btn_frame, text=text, font=('Segoe UI', 10, 'bold'),
                           bg=color, fg='white', relief=tk.FLAT,
                           activebackground=color, padx=20, pady=10,
                           command=cmd)
            btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # Monitor toggle (right side)
        self.monitor_label = tk.Label(btn_frame, text="", font=('Segoe UI', 9),
                                       fg='#888', bg=self.bg_dark)
        self.monitor_label.pack(side=tk.RIGHT, padx=(0, 10))
        
        self.monitor_btn = tk.Button(btn_frame, text="● Monitor", font=('Segoe UI', 9),
                                      bg=self.bg_mid, fg='#888', relief=tk.FLAT,
                                      activebackground=self.bg_light, padx=15, pady=8,
                                      command=self.toggle_monitor)
        self.monitor_btn.pack(side=tk.RIGHT)
    
    def create_history_tab(self):
        """Create the transaction history tab"""
        frame = self.history_tab
        
        content = tk.Frame(frame, bg=self.bg_dark)
        content.pack(fill=tk.BOTH, expand=True, padx=20, pady=15)
        
        # Header
        header = tk.Frame(content, bg=self.bg_dark)
        header.pack(fill=tk.X, pady=(0, 15))
        
        tk.Label(header, text="Transaction History", font=('Segoe UI', 14, 'bold'),
                 fg='#fff', bg=self.bg_dark).pack(side=tk.LEFT)
        
        refresh_btn = tk.Button(header, text="↻ Refresh", font=('Segoe UI', 9),
                                 bg=self.bg_mid, fg='#aaa', relief=tk.FLAT,
                                 padx=12, pady=4, command=self.refresh_history)
        refresh_btn.pack(side=tk.RIGHT)
        
        # Treeview container with rounded look
        tree_container = tk.Frame(content, bg=self.bg_mid, padx=2, pady=2)
        tree_container.pack(fill=tk.BOTH, expand=True)
        
        columns = ('date', 'type', 'amount', 'txid')
        self.history_tree = ttk.Treeview(tree_container, columns=columns, show='headings', height=15)
        self.history_tree.heading('date', text='Date')
        self.history_tree.heading('type', text='Type')
        self.history_tree.heading('amount', text='Amount')
        self.history_tree.heading('txid', text='Transaction ID (double-click to view)')
        self.history_tree.column('date', width=140, minwidth=120)
        self.history_tree.column('type', width=70, minwidth=60)
        self.history_tree.column('amount', width=120, minwidth=100)
        self.history_tree.column('txid', width=450, minwidth=200)
        
        # Scrollbars
        yscroll = ttk.Scrollbar(tree_container, orient=tk.VERTICAL, command=self.history_tree.yview)
        xscroll = ttk.Scrollbar(tree_container, orient=tk.HORIZONTAL, command=self.history_tree.xview)
        self.history_tree.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
        
        self.history_tree.grid(row=0, column=0, sticky='nsew')
        yscroll.grid(row=0, column=1, sticky='ns')
        xscroll.grid(row=1, column=0, sticky='ew')
        
        tree_container.grid_rowconfigure(0, weight=1)
        tree_container.grid_columnconfigure(0, weight=1)
        
        # Events
        self.history_tree.bind('<Double-1>', self.open_tx_in_explorer)
        
        # Right-click menu
        self.history_menu = tk.Menu(self.root, tearoff=0, bg=self.bg_mid, fg='#fff')
        self.history_menu.add_command(label="Copy TXID", command=self.copy_selected_txid)
        self.history_menu.add_command(label="View in Explorer", command=self.open_selected_tx)
        self.history_tree.bind('<Button-3>', self.show_history_menu)
        
        # Footer hint
        tk.Label(content, text="Right-click for options · Double-click to open in browser",
                 font=('Segoe UI', 9), fg='#666', bg=self.bg_dark).pack(pady=(10, 0))
    
    def create_keys_tab(self):
        """Create the key management tab"""
        frame = self.keys_tab
        
        content = tk.Frame(frame, bg=self.bg_dark)
        content.pack(fill=tk.BOTH, expand=True, padx=20, pady=15)
        
        # Current wallet card
        wallet_card = tk.Frame(content, bg=self.bg_mid, padx=20, pady=15)
        wallet_card.pack(fill=tk.X, pady=(0, 20))
        
        tk.Label(wallet_card, text="Current Wallet", font=('Segoe UI', 11, 'bold'),
                 fg='#fff', bg=self.bg_mid).pack(anchor=tk.W, pady=(0, 10))
        
        self.key_info_text = tk.Text(wallet_card, height=5, font=('Consolas', 10), 
                                      bg=self.bg_light, fg='#aaa', relief=tk.FLAT, 
                                      padx=12, pady=10)
        self.key_info_text.pack(fill=tk.X)
        self.key_info_text.config(state='disabled')
        
        # Key slot selector card
        slot_card = tk.Frame(content, bg=self.bg_mid, padx=20, pady=15)
        slot_card.pack(fill=tk.X, pady=(0, 20))
        
        tk.Label(slot_card, text="Key Slot", font=('Segoe UI', 11, 'bold'),
                 fg='#fff', bg=self.bg_mid).pack(anchor=tk.W, pady=(0, 10))
        
        slot_row = tk.Frame(slot_card, bg=self.bg_mid)
        slot_row.pack(fill=tk.X)
        
        tk.Label(slot_row, text="ID: 0x", font=('Consolas', 11), 
                 fg='#888', bg=self.bg_mid).pack(side=tk.LEFT)
        
        self.keyid_var = tk.StringVar(value=Config.KEY_ID)
        keyid_entry = tk.Entry(slot_row, textvariable=self.keyid_var, font=('Consolas', 11),
                               bg=self.bg_light, fg='#fff', relief=tk.FLAT, width=12,
                               insertbackground='#fff')
        keyid_entry.pack(side=tk.LEFT, padx=(0, 15), ipady=6)
        
        tk.Button(slot_row, text="Load", font=('Segoe UI', 9), bg='#3498db', fg='#fff',
                  relief=tk.FLAT, padx=15, pady=6, command=self.load_key_slot).pack(side=tk.LEFT, padx=(0, 5))
        
        tk.Button(slot_row, text="Check", font=('Segoe UI', 9), bg=self.bg_light, fg='#aaa',
                  relief=tk.FLAT, padx=15, pady=6, command=self.check_key_slot).pack(side=tk.LEFT)
        
        tk.Label(slot_card, text="Common: 20000001, 20000002, 20000003", 
                 font=('Segoe UI', 9), fg='#666', bg=self.bg_mid).pack(anchor=tk.W, pady=(10, 0))
        
        # Actions card
        action_card = tk.Frame(content, bg=self.bg_mid, padx=20, pady=15)
        action_card.pack(fill=tk.X, pady=(0, 20))
        
        tk.Label(action_card, text="Actions", font=('Segoe UI', 11, 'bold'),
                 fg='#fff', bg=self.bg_mid).pack(anchor=tk.W, pady=(0, 10))
        
        btn_row = tk.Frame(action_card, bg=self.bg_mid)
        btn_row.pack(fill=tk.X)

        tk.Button(btn_row, text="+ Create Wallet", font=('Segoe UI', 10, 'bold'),
                  bg='#27ae60', fg='#fff', relief=tk.FLAT, padx=15, pady=8,
                  command=self.show_create_wallet_dialog).pack(side=tk.LEFT, padx=(0, 10))

        tk.Button(btn_row, text="Import Seed", font=('Segoe UI', 10, 'bold'),
                  bg='#3498db', fg='#fff', relief=tk.FLAT, padx=15, pady=8,
                  command=self.show_import_wallet_dialog).pack(side=tk.LEFT, padx=(0, 10))

        tk.Button(btn_row, text="Export Pubkey", font=('Segoe UI', 10),
                  bg=self.bg_light, fg='#aaa', relief=tk.FLAT, padx=15, pady=8,
                  command=self.export_pubkey).pack(side=tk.LEFT, padx=(0, 10))

        tk.Button(btn_row, text="Wipe Key", font=('Segoe UI', 10),
                  bg='#c0392b', fg='#fff', relief=tk.FLAT, padx=15, pady=8,
                  command=self.wipe_key).pack(side=tk.LEFT)
        
        # SE050 status card
        se050_card = tk.Frame(content, bg=self.bg_mid, padx=20, pady=15)
        se050_card.pack(fill=tk.X)
        
        se050_header = tk.Frame(se050_card, bg=self.bg_mid)
        se050_header.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(se050_header, text="SE050 Status", font=('Segoe UI', 11, 'bold'),
                 fg='#fff', bg=self.bg_mid).pack(side=tk.LEFT)
        
        tk.Button(se050_header, text="↻", font=('Segoe UI', 10), bg=self.bg_mid, fg='#888',
                  relief=tk.FLAT, padx=8, command=self.refresh_se050_info).pack(side=tk.RIGHT)
        
        self.se050_info_text = tk.Text(se050_card, height=3, font=('Consolas', 10),
                                        bg=self.bg_light, fg='#aaa', relief=tk.FLAT,
                                        padx=12, pady=10)
        self.se050_info_text.pack(fill=tk.X)
        self.se050_info_text.config(state='disabled')
        
    def initial_load(self):
        """Initial connection and wallet load"""
        self.set_status("Connecting to SE050...", 'yellow')
        threading.Thread(target=self._connect_and_load, daemon=True).start()
    
    def _connect_and_load(self):
        """Background thread: connect and load wallet"""
        try:
            if se050_connect():
                self.connected = True
                self.root.after(0, lambda: self.set_status("SE050 Connected", 'green'))
                
                if self.wallet.load():
                    self.root.after(0, self.update_wallet_display)
                    self.root.after(0, self.update_key_info)
                    self.root.after(0, self.refresh_balance)
                    self.root.after(0, self.refresh_history)
                    self.root.after(0, self.refresh_se050_info)
                    # Update status to show wallet is ready
                    self.root.after(0, lambda: self.set_status(f"Wallet loaded (0x{Config.KEY_ID})", 'green'))
                else:
                    self.root.after(0, lambda: self.set_status("No wallet found - init from Keys tab", 'orange'))
                    self.root.after(0, self.update_key_info)
                    self.root.after(0, self.refresh_se050_info)
            else:
                self.root.after(0, lambda: self.set_status("SE050 Connection Failed", 'red'))
        except Exception as e:
            err_msg = str(e)
            self.root.after(0, lambda: self.set_status(f"Error: {err_msg}", 'red'))
    
    def set_status(self, text, color='gray'):
        """Update status indicator"""
        colors = {'green': '#2ecc71', 'red': '#e74c3c', 'yellow': '#f1c40f', 'orange': '#e67e22', 'gray': '#666'}
        self.status_label.config(text=text)
        self.status_indicator.itemconfig(self.status_dot, fill=colors.get(color, '#666'))
    
    def update_wallet_display(self):
        """Update UI with wallet data"""
        if not self.wallet.addresses:
            return
            
        self.segwit_var.set(self.wallet.addresses['segwit'])
        self.legacy_var.set(self.wallet.addresses['legacy'])
        self.update_qr()
    
    def update_qr(self):
        """Update QR code display"""
        if not self.wallet.addresses:
            return
            
        addr = self.wallet.addresses['segwit']
        
        if HAS_QR:
            try:
                qr = qrcode.QRCode(version=1, box_size=5, border=2)
                qr.add_data(addr)
                qr.make(fit=True)
                img = qr.make_image(fill_color="black", back_color="white").convert('RGB')
                # Resize to fit canvas (150x150, leave 2px margin)
                img = img.resize((146, 146))
                self.qr_image = ImageTk.PhotoImage(img)
                self.qr_canvas.delete("all")
                self.qr_canvas.create_image(75, 75, anchor=tk.CENTER, image=self.qr_image)
            except Exception as e:
                self.qr_canvas.delete("all")
                self.qr_canvas.create_text(75, 75, text=f"QR Error:\n{e}", fill='red', width=140)
        else:
            self.qr_canvas.delete("all")
            self.qr_canvas.create_text(75, 75, text="Install qrcode+pillow\nfor QR display", fill='#666', width=140)
    
    def refresh_balance(self):
        """Refresh balance from API"""
        if not self.wallet.addresses:
            return
        
        self.bottom_status.config(text="Fetching balance...")
        threading.Thread(target=self._fetch_balance, daemon=True).start()
    
    def _fetch_balance(self):
        """Background thread: fetch balance"""
        try:
            total = 0
            for addr in [self.wallet.addresses['segwit'], self.wallet.addresses['legacy']]:
                info = get_address_info(addr)
                if info:
                    funded = info['chain_stats']['funded_txo_sum']
                    spent = info['chain_stats']['spent_txo_sum']
                    total += funded - spent
            
            self.balance_sats = total
            self.btc_price = get_btc_price('USD')
            
            self.root.after(0, self._update_balance_display)
        except Exception as e:
            err_msg = str(e)
            self.root.after(0, lambda: self.bottom_status.config(text=f"Error: {err_msg}"))
    
    def _update_balance_display(self):
        """Update balance labels"""
        self.balance_label.config(text=f"{self.balance_sats:,}")
        
        if self.btc_price and self.balance_sats > 0:
            fiat = (self.balance_sats / 1e8) * self.btc_price
            self.fiat_label.config(text=f"sats  ≈  ${fiat:,.2f} USD")
        else:
            btc = self.balance_sats / 1e8
            self.fiat_label.config(text=f"sats  =  {btc:.8f} BTC")
        
        fees = get_fee_estimates()
        self.bottom_status.config(text=f"Network fees: {fees.get('fastestFee', '?')} sat/vB fast · {fees.get('hourFee', '?')} sat/vB slow")
    
    def toggle_monitor(self):
        """Toggle balance monitoring on/off"""
        if self.monitoring:
            self.monitoring = False
            self.monitor_btn.config(text="● Monitor", fg='#888')
            self.monitor_label.config(text="")
            self.bottom_status.config(text="Monitoring stopped")
        else:
            self.monitoring = True
            self.last_balance = self.balance_sats
            self.monitor_btn.config(text="■ Stop", fg='#e74c3c')
            self.bottom_status.config(text="Monitoring started...")
            self.monitor_countdown = self.monitor_interval
            self.monitor_loop()
    
    def monitor_loop(self):
        """Periodic balance check loop"""
        if not self.monitoring:
            return
        
        self.monitor_countdown -= 1
        
        if self.monitor_countdown <= 0:
            # Time to check
            self.monitor_label.config(text="checking...")
            threading.Thread(target=self._monitor_check, daemon=True).start()
            self.monitor_countdown = self.monitor_interval
        else:
            self.monitor_label.config(text=f"next: {self.monitor_countdown}s")
        
        # Schedule next tick
        if self.monitoring:
            self.root.after(1000, self.monitor_loop)
    
    def _monitor_check(self):
        """Background thread: check balance for changes"""
        try:
            total = 0
            for addr in [self.wallet.addresses['segwit'], self.wallet.addresses['legacy']]:
                info = get_address_info(addr)
                if info:
                    funded = info['chain_stats']['funded_txo_sum']
                    spent = info['chain_stats']['spent_txo_sum']
                    total += funded - spent
            
            self.btc_price = get_btc_price('USD')
            
            # Check for changes
            if total != self.last_balance:
                diff = total - self.last_balance
                self.last_balance = total
                self.balance_sats = total
                
                # Update UI and notify
                self.root.after(0, lambda: self._notify_balance_change(diff))
            else:
                self.root.after(0, lambda: self.monitor_label.config(text=f"next: {self.monitor_interval}s"))
            
            # Update display
            self.root.after(0, self._update_balance_display)
            
        except Exception as e:
            err_msg = str(e)
            self.root.after(0, lambda: self.bottom_status.config(text=f"Monitor error: {err_msg}"))
    
    def _notify_balance_change(self, diff_sats):
        """Notify user of balance change"""
        self.last_balance = self.balance_sats
        
        if diff_sats > 0:
            msg = f"💰 RECEIVED +{diff_sats:,} sats!"
            self.balance_label.config(fg='#2ecc71')  # Bright green
        else:
            msg = f"📤 SENT {diff_sats:,} sats"
            self.balance_label.config(fg='#e74c3c')  # Red
        
        self.bottom_status.config(text=msg)
        
        # Flash the window title
        self.root.title(msg)
        self.root.after(3000, lambda: self.root.title("SE050ARD Bitcoin Wallet"))
        
        # Reset balance color after delay
        self.root.after(5000, lambda: self.balance_label.config(fg='#2ecc71'))
        
        # Show popup for received funds
        if diff_sats > 0:
            self.root.bell()  # System beep
            messagebox.showinfo("Coins Received!", f"Received {diff_sats:,} sats\n\nNew balance: {self.balance_sats:,} sats")
    
    def copy_segwit(self):
        """Copy SegWit address to clipboard"""
        self.root.clipboard_clear()
        self.root.clipboard_append(self.segwit_var.get())
        self.bottom_status.config(text="SegWit address copied!")
    
    def copy_legacy(self):
        """Copy Legacy address to clipboard"""
        self.root.clipboard_clear()
        self.root.clipboard_append(self.legacy_var.get())
        self.bottom_status.config(text="Legacy address copied!")
    
    # History tab methods
    def refresh_history(self):
        """Refresh transaction history"""
        if not self.wallet.addresses:
            return
        self.bottom_status.config(text="Fetching transactions...")
        threading.Thread(target=self._fetch_history, daemon=True).start()
    
    def _fetch_history(self):
        """Background thread: fetch transaction history"""
        try:
            # Clear existing
            self.root.after(0, lambda: self.history_tree.delete(*self.history_tree.get_children()))
            
            all_txs = []
            our_addresses = {self.wallet.addresses['segwit'], self.wallet.addresses['legacy']}
            
            for addr in our_addresses:
                txs = get_address_txs(addr, limit=50)
                all_txs.extend(txs)
            
            # Dedupe
            seen = set()
            unique = []
            for tx in all_txs:
                if tx['txid'] not in seen:
                    seen.add(tx['txid'])
                    unique.append(tx)
            
            # Sort by time
            unique.sort(key=lambda x: x.get('status', {}).get('block_time', 0), reverse=True)
            
            for tx in unique[:50]:
                status = tx.get('status', {})
                block_time = status.get('block_time', 0)
                confirmed = status.get('confirmed', False)
                date_str = format_timestamp(block_time) if block_time else "⏳ Pending"
                
                # Calculate net
                total_in = sum(v.get('value', 0) for v in tx.get('vout', []) if v.get('scriptpubkey_address') in our_addresses)
                total_out = sum(vin.get('prevout', {}).get('value', 0) for vin in tx.get('vin', []) if vin.get('prevout', {}).get('scriptpubkey_address') in our_addresses)
                net = total_in - total_out
                
                if net > 0:
                    tx_type = "⬇ RECV"
                elif net < 0:
                    tx_type = "⬆ SEND"
                else:
                    tx_type = "↔ SELF"
                
                txid = tx['txid']
                
                self.root.after(0, lambda d=date_str, t=tx_type, a=net, tid=txid: 
                    self.history_tree.insert('', tk.END, values=(d, t, f"{a:+,}", tid)))
            
            self.root.after(0, lambda: self.bottom_status.config(text=f"Loaded {len(unique)} transactions"))
        except Exception as e:
            err_msg = str(e)
            self.root.after(0, lambda: self.bottom_status.config(text=f"Error: {err_msg}"))
    
    def show_history_menu(self, event):
        """Show right-click menu for history"""
        item = self.history_tree.identify_row(event.y)
        if item:
            self.history_tree.selection_set(item)
            self.history_menu.post(event.x_root, event.y_root)
    
    def get_selected_txid(self):
        """Get TXID of selected history item"""
        selection = self.history_tree.selection()
        if selection:
            item = self.history_tree.item(selection[0])
            return item['values'][3]  # txid is 4th column
        return None
    
    def copy_selected_txid(self):
        """Copy selected transaction ID"""
        txid = self.get_selected_txid()
        if txid:
            self.root.clipboard_clear()
            self.root.clipboard_append(txid)
            self.bottom_status.config(text=f"Copied: {txid[:16]}...")
    
    def open_selected_tx(self):
        """Open selected transaction in explorer"""
        txid = self.get_selected_txid()
        if txid:
            self.open_tx_url(txid)
    
    def open_tx_in_explorer(self, event):
        """Double-click handler to open tx in explorer"""
        txid = self.get_selected_txid()
        if txid:
            self.open_tx_url(txid)
    
    def open_tx_url(self, txid):
        """Open transaction in web browser"""
        import webbrowser
        explorer = "mempool.space/testnet4" if Config.NETWORK == "testnet" else "mempool.space"
        url = f"https://{explorer}/tx/{txid}"
        webbrowser.open(url)
        self.bottom_status.config(text=f"Opened {txid[:16]}... in browser")
    
    # Keys tab methods
    def update_key_info(self):
        """Update key info display"""
        self.key_info_text.config(state='normal')
        self.key_info_text.delete('1.0', tk.END)
        
        lines = []
        lines.append(f"  Key ID:     0x{Config.KEY_ID}")
        lines.append(f"  Network:    {Config.NETWORK}")
        
        if self.wallet.addresses:
            lines.append(f"  SegWit:     {self.wallet.addresses['segwit']}")
            lines.append(f"  Legacy:     {self.wallet.addresses['legacy']}")
            lines.append(f"  Pubkey:     {self.wallet.pubkey_compressed.hex()[:32]}...")
        else:
            lines.append(f"  Status:     No wallet loaded")
        
        self.key_info_text.insert('1.0', '\n'.join(lines))
        self.key_info_text.config(state='disabled')
    
    def refresh_se050_info(self):
        """Refresh SE050 status info"""
        self.bottom_status.config(text="Querying SE050...")
        threading.Thread(target=self._fetch_se050_info, daemon=True).start()
    
    def _fetch_se050_info(self):
        """Background: get SE050 info"""
        lines = []
        try:
            uid = se050_get_uid()
            if uid:
                lines.append(f"  UID:    {uid}")
            
            rng = se050_get_random()
            if rng:
                lines.append(f"  TRNG:   {rng.hex()}")
            
            if se050_key_exists(Config.KEY_ID):
                lines.append(f"  Key 0x{Config.KEY_ID}: Present ✓")
            else:
                lines.append(f"  Key 0x{Config.KEY_ID}: Not found")
            
            self.root.after(0, lambda: self._update_se050_display(lines))
        except Exception as e:
            err_msg = str(e)
            self.root.after(0, lambda: self._update_se050_display([f"  Error: {err_msg}"]))
    
    def _update_se050_display(self, lines):
        """Update SE050 info display"""
        self.se050_info_text.config(state='normal')
        self.se050_info_text.delete('1.0', tk.END)
        self.se050_info_text.insert('1.0', '\n'.join(lines))
        self.se050_info_text.config(state='disabled')
        self.bottom_status.config(text="SE050 info updated")
    
    def load_key_slot(self):
        """Load a different key slot"""
        new_keyid = self.keyid_var.get().strip()
        if not new_keyid:
            messagebox.showerror("Error", "Enter a key ID")
            return
        
        Config.KEY_ID = new_keyid
        self.wallet = Wallet()
        
        if self.wallet.load():
            self.update_wallet_display()
            self.update_key_info()
            self.refresh_balance()
            self.bottom_status.config(text=f"Loaded key slot 0x{new_keyid}")
        else:
            self.segwit_var.set("---")
            self.legacy_var.set("---")
            self.balance_label.config(text="--- sats")
            self.update_key_info()
            self.bottom_status.config(text=f"No wallet at slot 0x{new_keyid}")
    
    def check_key_slot(self):
        """Check if key exists in SE050"""
        keyid = self.keyid_var.get().strip()
        if se050_key_exists(keyid):
            messagebox.showinfo("Key Check", f"Key 0x{keyid} EXISTS in SE050")
        else:
            messagebox.showinfo("Key Check", f"Key 0x{keyid} NOT FOUND in SE050")
    
    def show_create_wallet_dialog(self):
        """Show dialog to create new wallet with seed phrase"""
        keyid = self.keyid_var.get().strip()

        # Check if key already exists
        if se050_key_exists(keyid):
            if not messagebox.askyesno("Warning", f"Key 0x{keyid} already exists!\n\nThis will REPLACE the existing key.\n\nContinue?"):
                return

        CreateWalletDialog(self.root, self, keyid)

    def show_import_wallet_dialog(self):
        """Show dialog to import wallet from seed phrase"""
        keyid = self.keyid_var.get().strip()

        # Check if key already exists
        if se050_key_exists(keyid):
            if not messagebox.askyesno("Warning", f"Key 0x{keyid} already exists!\n\nImporting will REPLACE the existing key.\n\nContinue?"):
                return

        ImportWalletDialog(self.root, self, keyid)

    def finalize_wallet_from_seed(self, mnemonic: str, keyid: str):
        """Create wallet from seed phrase and write to SE050"""
        Config.KEY_ID = keyid
        self.bottom_status.config(text="Deriving key from seed...")
        threading.Thread(target=lambda: self._finalize_wallet_from_seed(mnemonic), daemon=True).start()

    def _finalize_wallet_from_seed(self, mnemonic: str):
        """Background: derive key from seed and write to SE050"""
        try:
            # Convert mnemonic to seed
            seed = mnemonic_to_seed(mnemonic)

            # Derive BIP84 key (native segwit): m/84'/0'/0'/0/0
            coin_type = 1 if Config.NETWORK == "testnet" else 0
            private_key, pubkey_uncompressed = derive_bip84_key(seed, coin_type=coin_type)

            self.root.after(0, lambda: self.bottom_status.config(text="Writing key to SE050..."))

            # Connect to SE050
            if not se050_connect():
                self.root.after(0, lambda: messagebox.showerror("Error", "SE050 connection failed"))
                return

            # Delete existing key if present
            if se050_key_exists(Config.KEY_ID):
                se050_delete_key(Config.KEY_ID)

            # Write private key to SE050
            if not se050_set_ecc_keypair(Config.KEY_ID, private_key):
                self.root.after(0, lambda: messagebox.showerror("Error", "Failed to write key to SE050"))
                return

            # Export public key from SE050 to verify
            pubkey_path = Config.pubkey_der_path()
            Config.WALLET_DIR.mkdir(parents=True, exist_ok=True)
            if not se050_export_pubkey(Config.KEY_ID, pubkey_path, "DER"):
                self.root.after(0, lambda: messagebox.showerror("Error", "Pubkey export failed"))
                return

            # Load wallet
            self.wallet = Wallet()
            if self.wallet.load():
                self.wallet.save_info()
                self.root.after(0, self.update_wallet_display)
                self.root.after(0, self.update_key_info)
                self.root.after(0, self.refresh_balance)
                self.root.after(0, lambda: self.set_status(f"Wallet loaded (0x{Config.KEY_ID})", 'green'))
                self.root.after(0, lambda: self.bottom_status.config(text="Wallet created successfully!"))
                self.root.after(0, lambda: messagebox.showinfo("Success",
                    f"Wallet created!\n\n"
                    f"Key ID: 0x{Config.KEY_ID}\n"
                    f"SegWit: {self.wallet.addresses['segwit']}\n\n"
                    f"Key is now stored on SE050.\n"
                    f"Keep your seed phrase backup safe!"))
            else:
                self.root.after(0, lambda: messagebox.showerror("Error", "Failed to load wallet"))
        except Exception as e:
            err_msg = str(e)
            self.root.after(0, lambda: messagebox.showerror("Error", f"Wallet creation failed: {err_msg}"))
    
    def export_pubkey(self):
        """Export public key info"""
        if not self.wallet.addresses:
            messagebox.showerror("Error", "No wallet loaded")
            return
        
        info = f"Key ID: 0x{Config.KEY_ID}\n"
        info += f"Network: {Config.NETWORK}\n\n"
        info += f"Compressed Pubkey (hex):\n{self.wallet.pubkey_compressed.hex()}\n\n"
        info += f"SegWit Address:\n{self.wallet.addresses['segwit']}\n\n"
        info += f"Legacy Address:\n{self.wallet.addresses['legacy']}"
        
        # Show in dialog with copy button
        dialog = tk.Toplevel(self.root)
        dialog.title("Public Key Export")
        dialog.geometry("520x380")
        dialog.configure(bg=self.bg_dark)
        
        content = tk.Frame(dialog, bg=self.bg_dark, padx=20, pady=20)
        content.pack(fill=tk.BOTH, expand=True)
        
        tk.Label(content, text="Public Key Export", font=('Segoe UI', 14, 'bold'),
                 fg=self.accent, bg=self.bg_dark).pack(anchor=tk.W, pady=(0, 15))
        
        text = tk.Text(content, font=('Consolas', 10), bg=self.bg_mid, fg='#aaa', 
                       relief=tk.FLAT, padx=12, pady=12)
        text.pack(fill=tk.BOTH, expand=True)
        text.insert('1.0', info)
        text.config(state='disabled')
        
        def copy_all():
            self.root.clipboard_clear()
            self.root.clipboard_append(info)
            self.bottom_status.config(text="Public key info copied!")
        
        tk.Button(content, text="Copy All", font=('Segoe UI', 10),
                  bg=self.accent_blue, fg='white', relief=tk.FLAT,
                  padx=15, pady=8, command=copy_all).pack(pady=(15, 0))
    
    def wipe_key(self):
        """Wipe key from SE050"""
        keyid = self.keyid_var.get().strip()
        
        msg = f"⚠️ DANGER: WIPE KEY 0x{keyid}? ⚠️\n\n"
        msg += "This will PERMANENTLY DELETE:\n"
        msg += "• The private key from SE050\n"
        msg += "• All access to funds at this address\n\n"
        msg += "This CANNOT be undone!\n\n"
        msg += "Type 'WIPE' to confirm:"
        
        confirm = simpledialog.askstring("Confirm Wipe", msg, parent=self.root)
        if confirm != "WIPE":
            self.bottom_status.config(text="Wipe cancelled")
            return
        
        try:
            se050_delete_key(keyid)
            
            # Delete local files
            for path in [Config.pubkey_der_path(), Config.pubkey_pem_path(), Config.wallet_info_path()]:
                if path.exists():
                    path.unlink()
            
            self.wallet = Wallet()
            self.segwit_var.set("---")
            self.legacy_var.set("---")
            self.balance_label.config(text="--- sats")
            self.update_key_info()
            
            messagebox.showinfo("Wiped", f"Key 0x{keyid} has been wiped")
        except Exception as e:
            messagebox.showerror("Error", f"Wipe failed: {e}")
    
    def show_send_dialog(self):
        """Show send transaction dialog"""
        if not self.wallet.addresses:
            messagebox.showerror("Error", "No wallet loaded")
            return
        
        dialog = SendDialog(self.root, self)
        self.root.wait_window(dialog.top)
    
    def show_sign_dialog(self):
        """Show message signing dialog"""
        if not self.wallet.addresses:
            messagebox.showerror("Error", "No wallet loaded")
            return
        
        message = simpledialog.askstring("Sign Message", "Enter message to sign:", parent=self.root)
        if not message:
            return
        
        self.bottom_status.config(text="Signing with SE050...")
        threading.Thread(target=lambda: self._sign_message(message), daemon=True).start()
    
    def _sign_message(self, message):
        """Background thread: sign message"""
        try:
            if not se050_connect():
                self.root.after(0, lambda: messagebox.showerror("Error", "SE050 connection failed"))
                return
            
            (r, s), recovery_id = sign_message_with_se050(Config.KEY_ID, message)
            signature = encode_signed_message(r, s, recovery_id, compressed=True)
            
            # Show result
            self.root.after(0, lambda: self._show_signature_result(message, signature))
        except Exception as e:
            err_msg = str(e)
            self.root.after(0, lambda: messagebox.showerror("Error", f"Signing failed: {err_msg}"))
    
    def _show_signature_result(self, message, signature):
        """Show signed message result"""
        result_window = tk.Toplevel(self.root)
        result_window.title("Signed Message")
        result_window.geometry("520x320")
        result_window.configure(bg=self.bg_dark)
        
        content = tk.Frame(result_window, bg=self.bg_dark, padx=20, pady=20)
        content.pack(fill=tk.BOTH, expand=True)
        
        tk.Label(content, text="Signed Message", font=('Segoe UI', 14, 'bold'),
                 fg=self.accent, bg=self.bg_dark).pack(anchor=tk.W, pady=(0, 15))
        
        # Message
        tk.Label(content, text="MESSAGE", font=('Segoe UI', 9),
                 fg=self.fg_dim, bg=self.bg_dark).pack(anchor=tk.W)
        msg_text = tk.Text(content, height=2, font=('Consolas', 10), 
                           bg=self.bg_mid, fg='#aaa', relief=tk.FLAT, padx=8, pady=8)
        msg_text.insert(tk.END, message)
        msg_text.config(state='disabled')
        msg_text.pack(fill=tk.X, pady=(2, 10))
        
        # Address
        tk.Label(content, text="ADDRESS", font=('Segoe UI', 9),
                 fg=self.fg_dim, bg=self.bg_dark).pack(anchor=tk.W)
        tk.Label(content, text=self.wallet.addresses['legacy'], font=('Consolas', 10),
                 fg=self.accent_blue, bg=self.bg_dark).pack(anchor=tk.W, pady=(2, 10))
        
        # Signature
        tk.Label(content, text="SIGNATURE", font=('Segoe UI', 9),
                 fg=self.fg_dim, bg=self.bg_dark).pack(anchor=tk.W)
        sig_text = tk.Text(content, height=2, font=('Consolas', 10),
                           bg=self.bg_mid, fg='#aaa', relief=tk.FLAT, padx=8, pady=8)
        sig_text.insert(tk.END, signature)
        sig_text.config(state='disabled')
        sig_text.pack(fill=tk.X, pady=(2, 15))
        
        def copy_sig():
            self.root.clipboard_clear()
            self.root.clipboard_append(signature)
            self.bottom_status.config(text="Signature copied!")
        
        tk.Button(content, text="Copy Signature", font=('Segoe UI', 10),
                  bg=self.accent_blue, fg='white', relief=tk.FLAT,
                  padx=15, pady=8, command=copy_sig).pack()
        
        self.bottom_status.config(text="Message signed!")
    
    def verify_se050(self):
        """Verify SE050 is working"""
        self.bottom_status.config(text="Verifying SE050...")
        threading.Thread(target=self._verify_se050, daemon=True).start()
    
    def _verify_se050(self):
        """Background thread: verify SE050"""
        results = []
        
        try:
            # Test connection
            if se050_connect():
                results.append("✓ SE050 Connected")
            else:
                results.append("✗ Connection Failed")
                self.root.after(0, lambda: self._show_verify_results(results, False))
                return
            
            # Test UID
            uid = se050_get_uid()
            if uid:
                results.append(f"✓ UID: {uid[:16]}...")
            
            # Test key exists
            if se050_key_exists(Config.KEY_ID):
                results.append(f"✓ Key 0x{Config.KEY_ID} present")
            else:
                results.append(f"✗ Key 0x{Config.KEY_ID} not found")
            
            # Test signing
            test_hash = sha256(f"verify-{datetime.now().isoformat()}".encode())
            sig = se050_sign(Config.KEY_ID, test_hash)
            if sig and len(sig) > 60:
                results.append(f"✓ Signature generated ({len(sig)} bytes)")
            
            self.root.after(0, lambda: self._show_verify_results(results, True))
            
        except Exception as e:
            results.append(f"✗ Error: {e}")
            self.root.after(0, lambda: self._show_verify_results(results, False))
    
    def _show_verify_results(self, results, success):
        """Show verification results"""
        title = "Verification Passed" if success else "Verification Failed"
        icon = messagebox.INFO if success else messagebox.ERROR
        messagebox.showinfo(title, "\n".join(results))
        self.bottom_status.config(text="Verification complete" if success else "Verification failed")


class SendDialog:
    """Send transaction dialog"""
    
    def __init__(self, parent, gui):
        self.gui = gui
        
        # Colors
        self.bg = '#0f0f1a'
        self.bg_card = '#1a1a2e'
        self.bg_input = '#252540'
        self.fg = '#e8e8e8'
        self.fg_dim = '#888'
        
        self.top = tk.Toplevel(parent)
        self.top.title("Send Bitcoin")
        self.top.geometry("520x580")
        self.top.configure(bg=self.bg)
        self.top.transient(parent)
        self.top.grab_set()
        
        # Cache price for consistent calculations
        self.cached_prices = {}
        
        # Main content
        content = tk.Frame(self.top, bg=self.bg, padx=25, pady=20)
        content.pack(fill=tk.BOTH, expand=True)
        
        # Title
        tk.Label(content, text="Send Bitcoin", font=('Segoe UI', 16, 'bold'),
                 fg='#e74c3c', bg=self.bg).pack(anchor=tk.W, pady=(0, 20))
        
        # Destination
        tk.Label(content, text="To Address", font=('Segoe UI', 10),
                 fg=self.fg_dim, bg=self.bg).pack(anchor=tk.W)
        self.dest_var = tk.StringVar()
        dest_entry = tk.Entry(content, textvariable=self.dest_var, font=('Consolas', 11),
                              bg=self.bg_input, fg=self.fg, relief=tk.FLAT, insertbackground='#fff')
        dest_entry.pack(fill=tk.X, ipady=10, pady=(5, 15))
        
        # Amount row
        amount_row = tk.Frame(content, bg=self.bg)
        amount_row.pack(fill=tk.X, pady=(0, 15))
        
        amount_col = tk.Frame(amount_row, bg=self.bg)
        amount_col.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        tk.Label(amount_col, text="Amount", font=('Segoe UI', 10),
                 fg=self.fg_dim, bg=self.bg).pack(anchor=tk.W)
        
        amount_input = tk.Frame(amount_col, bg=self.bg)
        amount_input.pack(fill=tk.X, pady=(5, 0))
        
        self.amount_var = tk.StringVar()
        amount_entry = tk.Entry(amount_input, textvariable=self.amount_var, font=('Consolas', 14),
                                bg=self.bg_input, fg=self.fg, relief=tk.FLAT, width=12,
                                insertbackground='#fff')
        amount_entry.pack(side=tk.LEFT, ipady=8)
        amount_entry.bind('<KeyRelease>', lambda e: self.update_calculation())
        
        self.unit_var = tk.StringVar(value="sats")
        unit_combo = ttk.Combobox(amount_input, textvariable=self.unit_var, 
                                   values=["sats", "BTC", "USD", "EUR", "GBP"], 
                                   width=5, state='readonly', font=('Segoe UI', 10))
        unit_combo.pack(side=tk.LEFT, padx=(10, 0))
        unit_combo.bind('<<ComboboxSelected>>', lambda e: self.update_calculation())
        
        max_btn = tk.Button(amount_input, text="MAX", font=('Segoe UI', 9, 'bold'),
                            bg='#3498db', fg='#fff', relief=tk.FLAT, padx=12, pady=6,
                            command=self.set_max_amount)
        max_btn.pack(side=tk.LEFT, padx=(10, 0))
        
        # Fee section - fetch live rates
        self.fee_estimates = get_fee_estimates()
        
        fee_section = tk.Frame(content, bg=self.bg)
        fee_section.pack(fill=tk.X, pady=(0, 15))
        
        tk.Label(fee_section, text="Network Fee", font=('Segoe UI', 10),
                 fg=self.fg_dim, bg=self.bg).pack(anchor=tk.W)
        
        fee_row = tk.Frame(fee_section, bg=self.bg)
        fee_row.pack(fill=tk.X, pady=(5, 0))
        
        # Priority buttons
        self.fee_var = tk.StringVar(value=str(self.fee_estimates.get('halfHourFee', 10)))
        self.fee_priority = tk.StringVar(value="medium")
        
        priorities = [
            ("🐢 Slow", "slow", self.fee_estimates.get('hourFee', 5), '#666'),
            ("⚡ Medium", "medium", self.fee_estimates.get('halfHourFee', 10), '#f39c12'),
            ("🚀 Fast", "fast", self.fee_estimates.get('fastestFee', 20), '#27ae60'),
        ]
        
        for label, priority, rate, color in priorities:
            btn = tk.Button(fee_row, text=f"{label}\n{rate} sat/vB", 
                           font=('Segoe UI', 9), bg=self.bg_card, fg=self.fg,
                           relief=tk.FLAT, padx=12, pady=6, width=10,
                           command=lambda r=rate, p=priority: self.set_fee_priority(r, p))
            btn.pack(side=tk.LEFT, padx=(0, 8))
            # Store reference for highlighting
            setattr(self, f'fee_btn_{priority}', btn)
        
        # Custom fee entry
        tk.Label(fee_row, text="or", font=('Segoe UI', 9), 
                 fg=self.fg_dim, bg=self.bg).pack(side=tk.LEFT, padx=(5, 5))
        
        fee_entry = tk.Entry(fee_row, textvariable=self.fee_var, font=('Consolas', 11),
                             bg=self.bg_input, fg=self.fg, relief=tk.FLAT, width=5,
                             insertbackground='#fff')
        fee_entry.pack(side=tk.LEFT, ipady=6)
        fee_entry.bind('<KeyRelease>', lambda e: self.on_custom_fee())
        
        tk.Label(fee_row, text="sat/vB", font=('Segoe UI', 9), 
                 fg=self.fg_dim, bg=self.bg).pack(side=tk.LEFT, padx=(5, 0))
        
        # Highlight default (medium)
        self.highlight_fee_button("medium")
        
        # Breakdown card
        breakdown_card = tk.Frame(content, bg=self.bg_card, padx=15, pady=15)
        breakdown_card.pack(fill=tk.X, pady=(5, 15))
        
        tk.Label(breakdown_card, text="Transaction Summary", font=('Segoe UI', 10, 'bold'),
                 fg=self.fg, bg=self.bg_card).pack(anchor=tk.W, pady=(0, 10))
        
        self.calc_text = tk.Text(breakdown_card, height=7, font=('Consolas', 10), 
                                  bg=self.bg_card, fg='#aaa', relief=tk.FLAT)
        self.calc_text.pack(fill=tk.X)
        self.calc_text.config(state='disabled')
        
        # Buttons
        btn_frame = tk.Frame(content, bg=self.bg)
        btn_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.send_btn = tk.Button(btn_frame, text="Send", font=('Segoe UI', 11, 'bold'),
                                   bg='#e74c3c', fg='#fff', relief=tk.FLAT, 
                                   padx=30, pady=10, command=self.send)
        self.send_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        cancel_btn = tk.Button(btn_frame, text="Cancel", font=('Segoe UI', 11),
                                bg=self.bg_card, fg=self.fg_dim, relief=tk.FLAT,
                                padx=20, pady=10, command=self.top.destroy)
        cancel_btn.pack(side=tk.LEFT)
        
        self.status_label = tk.Label(btn_frame, text="", font=('Segoe UI', 9),
                                      fg=self.fg_dim, bg=self.bg)
        self.status_label.pack(side=tk.RIGHT)
        
        # Initial calc
        self.update_calculation()
    
    def set_fee_priority(self, rate, priority):
        """Set fee from priority button"""
        self.fee_var.set(str(rate))
        self.fee_priority.set(priority)
        self.highlight_fee_button(priority)
        self.update_calculation()
    
    def on_custom_fee(self):
        """Handle custom fee entry"""
        self.fee_priority.set("custom")
        self.highlight_fee_button("custom")
        self.update_calculation()
    
    def highlight_fee_button(self, active_priority):
        """Highlight the active fee priority button"""
        colors = {
            'slow': ('#666', '#888'),
            'medium': ('#f39c12', '#ffc107'),
            'fast': ('#27ae60', '#2ecc71'),
        }
        for priority in ['slow', 'medium', 'fast']:
            btn = getattr(self, f'fee_btn_{priority}', None)
            if btn:
                if priority == active_priority:
                    # Active - highlighted
                    btn.config(bg=colors[priority][1], fg='#000')
                else:
                    # Inactive
                    btn.config(bg=self.bg_card, fg=self.fg)
    
    def get_price(self, currency):
        """Get cached price or fetch new one"""
        if currency not in self.cached_prices:
            self.cached_prices[currency] = get_btc_price(currency)
        return self.cached_prices[currency]
    
    def sats_to_unit(self, sats, unit):
        """Convert sats to display unit"""
        if unit == "sats":
            return f"{sats:,} sats"
        elif unit == "BTC":
            return f"{sats / 100_000_000:.8f} BTC"
        else:
            price = self.get_price(unit)
            if price:
                fiat = (sats / 100_000_000) * price
                symbols = {"USD": "$", "EUR": "€", "GBP": "£"}
                return f"{symbols.get(unit, '')}{fiat:.2f} {unit}"
            return f"{sats:,} sats"
    
    def get_amount_sats(self):
        """Parse amount field and return sats"""
        amount_str = self.amount_var.get().strip()
        if not amount_str:
            return 0
        
        unit = self.unit_var.get()
        try:
            if unit == "sats":
                return int(float(amount_str))
            elif unit == "BTC":
                return int(float(amount_str) * 100_000_000)
            else:
                price = self.get_price(unit)
                if price:
                    fiat = float(amount_str)
                    btc = fiat / price
                    return int(btc * 100_000_000)
        except:
            pass
        return 0
    
    def update_calculation(self):
        """Update the transaction breakdown display"""
        self.calc_text.config(state='normal')
        self.calc_text.delete('1.0', tk.END)
        
        unit = self.unit_var.get()
        amount_sats = self.get_amount_sats()
        
        try:
            fee_rate = int(self.fee_var.get().strip())
        except:
            fee_rate = 10
        
        balance_sats = self.gui.balance_sats
        
        # Estimate tx size (assumes SegWit, 1-2 inputs typical)
        # P2WPKH: ~110 base + 68 per input
        est_inputs = max(1, (amount_sats // 50000) + 1) if amount_sats > 0 else 1
        est_vsize = 110 + (68 * est_inputs)
        fee_sats = est_vsize * fee_rate
        
        total_needed = amount_sats + fee_sats
        change_sats = balance_sats - total_needed if balance_sats >= total_needed else 0
        
        # Build display
        lines = []
        lines.append(f"  Available balance: {self.sats_to_unit(balance_sats, unit)}")
        lines.append(f"")
        lines.append(f"  Recipient gets:    {self.sats_to_unit(amount_sats, unit)}")
        lines.append(f"  Network fee:       {self.sats_to_unit(fee_sats, unit)} (~{est_vsize} vB × {fee_rate} sat/vB)")
        lines.append(f"  ────────────────────────────────────")
        lines.append(f"  Total from wallet: {self.sats_to_unit(total_needed, unit)}")
        lines.append(f"  Change returned:   {self.sats_to_unit(change_sats, unit)}")
        
        if balance_sats < total_needed:
            shortfall = total_needed - balance_sats
            lines.append(f"")
            lines.append(f"  ⚠️  INSUFFICIENT: need {self.sats_to_unit(shortfall, unit)} more")
            self.send_btn.config(state='disabled')
        elif amount_sats <= 0:
            lines.append(f"")
            lines.append(f"  Enter an amount to send")
            self.send_btn.config(state='disabled')
        else:
            self.send_btn.config(state='normal')
        
        self.calc_text.insert('1.0', '\n'.join(lines))
        self.calc_text.config(state='disabled')
    
    def set_max_amount(self):
        """Set amount to max recipient can receive (balance minus fees)"""
        try:
            fee_rate = int(self.fee_var.get().strip())
        except:
            fee_rate = self.fee_estimates.get('halfHourFee', 10)
        
        # Estimate fee for typical tx (conservative - assume 2 inputs)
        est_vsize = 110 + (68 * 2)  # ~246 vB
        fee_sats = est_vsize * fee_rate
        max_sats = max(0, self.gui.balance_sats - fee_sats)
        
        unit = self.unit_var.get()
        
        if unit == "sats":
            self.amount_var.set(str(max_sats))
        elif unit == "BTC":
            self.amount_var.set(f"{max_sats / 100_000_000:.8f}")
        else:
            price = self.get_price(unit)
            if price:
                fiat = (max_sats / 100_000_000) * price
                self.amount_var.set(f"{fiat:.2f}")
            else:
                self.unit_var.set("sats")
                self.amount_var.set(str(max_sats))
        
        self.update_calculation()
    
    def send(self):
        """Execute send"""
        dest = self.dest_var.get().strip()
        if not dest:
            messagebox.showerror("Error", "Enter destination address")
            return
        
        # Validate destination address
        try:
            create_output_script(dest)
        except Exception as e:
            messagebox.showerror("Error", f"Invalid destination address:\n{e}")
            return
        
        amount_sats = self.get_amount_sats()
        if amount_sats <= 0:
            messagebox.showerror("Error", "Enter a valid amount")
            return
        
        if amount_sats < 546:
            messagebox.showerror("Error", "Amount too small (dust limit: 546 sats)")
            return
        
        try:
            fee_rate = int(self.fee_var.get().strip())
            if fee_rate < 1:
                raise ValueError("Fee rate must be at least 1")
        except Exception as e:
            messagebox.showerror("Error", f"Invalid fee rate: {e}")
            return
        
        unit = self.unit_var.get()
        balance_sats = self.gui.balance_sats
        
        # Use same fee calculation as update_calculation for consistency
        est_inputs = max(1, (amount_sats // 50000) + 1) if amount_sats > 0 else 1
        est_vsize = 110 + (68 * est_inputs)
        fee_sats = est_vsize * fee_rate
        total = amount_sats + fee_sats
        
        if balance_sats < total:
            shortfall = total - balance_sats
            messagebox.showerror("Error", f"Insufficient funds!\n\nNeed: {self.sats_to_unit(total, unit)}\nHave: {self.sats_to_unit(balance_sats, unit)}\nShort: {self.sats_to_unit(shortfall, unit)}")
            return
        
        change_sats = balance_sats - total
        
        # Build confirmation message
        msg = f"CONFIRM TRANSACTION\n\n"
        msg += f"Send:   {self.sats_to_unit(amount_sats, unit)}\n"
        msg += f"Fee:    {self.sats_to_unit(fee_sats, unit)} ({est_vsize} vB × {fee_rate} sat/vB)\n"
        msg += f"Total:  {self.sats_to_unit(total, unit)}\n"
        if change_sats > 546:
            msg += f"Change: {self.sats_to_unit(change_sats, unit)}\n"
        msg += f"\nTo: {dest[:20]}...{dest[-8:]}\n\n"
        msg += f"Proceed?"
        
        if not messagebox.askyesno("Confirm Send", msg):
            return
        
        self.status_label.config(text="Building transaction...")
        self.send_btn.config(state='disabled')
        threading.Thread(target=lambda: self._execute_send(dest, amount_sats, fee_rate), daemon=True).start()
    
    def _execute_send(self, dest, amount_sats, fee_rate):
        """Background thread: execute send"""
        def on_error(msg):
            """Helper to show error and re-enable button"""
            self.top.after(0, lambda: messagebox.showerror("Error", msg))
            self.top.after(0, lambda: self.send_btn.config(state='normal'))
            self.top.after(0, lambda: self.status_label.config(text=""))
        
        try:
            wallet = self.gui.wallet
            
            # Connect
            if not se050_connect():
                on_error("SE050 connection failed.\n\nCheck hardware connection.")
                return
            
            # Get UTXOs
            self.top.after(0, lambda: self.status_label.config(text="Fetching UTXOs..."))
            utxos = get_utxos(wallet.addresses['segwit'])
            if not utxos:
                utxos = get_utxos(wallet.addresses['legacy'])
            
            if not utxos:
                on_error("No UTXOs available.\n\nWait for pending transactions to confirm.")
                return
            
            total_in = sum(u['value'] for u in utxos)
            est_vsize = 110 + (68 * len(utxos))
            fee = est_vsize * fee_rate
            
            unit = self.unit_var.get()
            
            if total_in < amount_sats + fee:
                shortfall = (amount_sats + fee) - total_in
                msg = f"Insufficient funds\n\nHave: {self.sats_to_unit(total_in, unit)}\nNeed: {self.sats_to_unit(amount_sats + fee, unit)}\nShort: {self.sats_to_unit(shortfall, unit)}"
                on_error(msg)
                return
            
            change = total_in - amount_sats - fee
            
            # Build inputs/outputs
            inputs = [{'txid': u['txid'], 'vout': u['vout'], 'value': u['value']} for u in utxos]
            outputs = [{'value': amount_sats, 'script': create_output_script(dest)}]
            
            if change > 546:
                change_script = bytes([0x00, 0x14]) + hash160(wallet.pubkey_compressed)
                outputs.append({'value': change, 'script': change_script})
            
            self.top.after(0, lambda: self.status_label.config(text="Signing with SE050..."))
            
            # Sign
            try:
                raw_tx = build_and_sign_transaction(inputs, outputs, wallet.pubkey_compressed, wallet.pubkey_hash)
            except Exception as sign_err:
                on_error(f"Signing failed:\n{sign_err}")
                return
            
            tx_hex = raw_tx.hex()
            
            self.top.after(0, lambda: self.status_label.config(text="Broadcasting..."))
            
            # Broadcast
            txid = api_post("/tx", tx_hex.encode())
            
            if txid:
                self.top.after(0, lambda: self._send_success(txid, amount_sats, fee))
            else:
                on_error("Broadcast failed.\n\nThe transaction may be invalid or the network is unavailable.")
                
        except Exception as e:
            err_msg = str(e)
            on_error(f"Send failed:\n{err_msg}")
    
    def _send_success(self, txid, amount_sats, fee_sats):
        """Handle successful send"""
        unit = self.unit_var.get()
        explorer = "mempool.space/testnet4" if Config.NETWORK == "testnet" else "mempool.space"
        
        msg = f"Transaction broadcast!\n\n"
        msg += f"Sent: {self.sats_to_unit(amount_sats, unit)}\n"
        msg += f"Fee: {self.sats_to_unit(fee_sats, unit)}\n\n"
        msg += f"TXID:\n{txid}\n\n"
        msg += f"https://{explorer}/tx/{txid}"
        
        messagebox.showinfo("Success!", msg)
        self.top.destroy()
        self.gui.refresh_balance()


class CreateWalletDialog:
    """Dialog for creating a new wallet with seed phrase"""

    def __init__(self, parent, gui, keyid):
        self.gui = gui
        self.keyid = keyid
        self.mnemonic = None
        self.confirmed = False
        self.word_count = 12  # Default to 12 words
        self.lazy_mode = False  # Lazy mode skips verification, allows clipboard copy

        # Colors
        self.bg = '#0f0f1a'
        self.bg_card = '#1a1a2e'
        self.bg_input = '#252540'
        self.fg = '#e8e8e8'
        self.fg_dim = '#888'
        self.accent = '#f39c12'
        self.accent_green = '#27ae60'
        self.accent_red = '#e74c3c'
        self.accent_yolo = '#ff6b6b'  # YOLO color

        self.top = tk.Toplevel(parent)
        self.top.title("Create New Wallet")
        self.top.geometry("620x780")  # Taller to fit 24 words + buttons
        self.top.configure(bg=self.bg)
        self.top.transient(parent)
        self.top.grab_set()
        
        # Bind cleanup on close
        self.top.protocol("WM_DELETE_WINDOW", self.on_close)

        self.create_step1()
    
    def on_close(self):
        """Clean up mnemonic from memory on close"""
        if self.mnemonic:
            self.mnemonic = None
        self.top.destroy()

    def create_step1(self):
        """Step 1: Generate and display seed phrase"""
        # Generate mnemonic based on word count
        strength = 256 if self.word_count == 24 else 128
        self.mnemonic = generate_mnemonic(strength)
        
        # Resize window based on word count
        height = 850 if self.word_count == 24 else 750
        self.top.geometry(f"620x{height}")

        # Clear window
        for widget in self.top.winfo_children():
            widget.destroy()

        content = tk.Frame(self.top, bg=self.bg, padx=30, pady=25)
        content.pack(fill=tk.BOTH, expand=True)

        # Title
        tk.Label(content, text="WRITE DOWN YOUR SEED PHRASE", font=('Segoe UI', 16, 'bold'),
                 fg=self.accent, bg=self.bg).pack(anchor=tk.W, pady=(0, 5))

        tk.Label(content, text=f"These {self.word_count} words are your wallet backup. Write them down NOW!",
                 font=('Segoe UI', 10), fg=self.fg_dim, bg=self.bg).pack(anchor=tk.W, pady=(0, 15))

        # Word count selector
        wc_frame = tk.Frame(content, bg=self.bg)
        wc_frame.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(wc_frame, text="Seed length:", font=('Segoe UI', 9),
                 fg=self.fg_dim, bg=self.bg).pack(side=tk.LEFT)
        
        self.wc_var = tk.IntVar(value=self.word_count)
        for wc in [12, 24]:
            rb = tk.Radiobutton(wc_frame, text=f"{wc} words", variable=self.wc_var, value=wc,
                               font=('Segoe UI', 9), bg=self.bg, fg=self.fg,
                               selectcolor=self.bg_card, activebackground=self.bg,
                               command=self.on_word_count_change)
            rb.pack(side=tk.LEFT, padx=(15, 0))
        
        # Lazy mode toggle
        lazy_frame = tk.Frame(content, bg=self.bg_card, padx=12, pady=10)
        lazy_frame.pack(fill=tk.X, pady=(0, 15))
        
        self.lazy_var = tk.BooleanVar(value=self.lazy_mode)
        lazy_cb = tk.Checkbutton(lazy_frame, text="🦥 Lazy Mode (skip verification, enable copy)", 
                                 variable=self.lazy_var, font=('Segoe UI', 10),
                                 bg=self.bg_card, fg=self.accent_yolo,
                                 selectcolor=self.bg_input, activebackground=self.bg_card,
                                 command=self.on_lazy_toggle)
        lazy_cb.pack(anchor=tk.W)
        
        lazy_warning = tk.Label(lazy_frame, 
                               text="⚠️ YOLO mode: Less secure, but you do you",
                               font=('Segoe UI', 8), fg='#ff9999', bg=self.bg_card)
        lazy_warning.pack(anchor=tk.W, padx=(20, 0))

        # Warning (hidden in lazy mode)
        self.warn_frame = tk.Frame(content, bg='#8B0000', padx=15, pady=12)
        self.warn_frame.pack(fill=tk.X, pady=(0, 15))
        tk.Label(self.warn_frame, text="WARNING: If you lose these words, you lose your Bitcoin forever!",
                 font=('Segoe UI', 10, 'bold'), fg='#fff', bg='#8B0000').pack()
        tk.Label(self.warn_frame, text="Never share them. Never store them digitally. Write on paper only.",
                 font=('Segoe UI', 9), fg='#ffcccc', bg='#8B0000').pack()

        # Seed phrase display
        seed_frame = tk.Frame(content, bg=self.bg_card, padx=20, pady=20)
        seed_frame.pack(fill=tk.X, pady=(0, 15))

        words = self.mnemonic.split()
        cols = 3 if self.word_count == 12 else 4
        rows = self.word_count // cols
        
        for i in range(0, self.word_count, cols):
            row = tk.Frame(seed_frame, bg=self.bg_card)
            row.pack(fill=tk.X, pady=4)
            for j in range(cols):
                idx = i + j
                if idx >= self.word_count:
                    break
                word_frame = tk.Frame(row, bg=self.bg_input, padx=8, pady=6)
                word_frame.pack(side=tk.LEFT, padx=4, expand=True, fill=tk.X)
                tk.Label(word_frame, text=f"{idx+1}.", font=('Consolas', 10),
                         fg=self.fg_dim, bg=self.bg_input, width=3).pack(side=tk.LEFT)
                tk.Label(word_frame, text=words[idx], font=('Consolas', 12, 'bold'),
                         fg=self.accent_green, bg=self.bg_input).pack(side=tk.LEFT, padx=(3, 0))

        # Copy button (only visible in lazy mode)
        self.copy_frame = tk.Frame(content, bg=self.bg)
        self.copy_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.copy_btn = tk.Button(self.copy_frame, text="📋 Copy All Words to Clipboard", 
                                  font=('Segoe UI', 10, 'bold'),
                                  bg=self.accent_yolo, fg='#000', relief=tk.FLAT, padx=15, pady=8,
                                  command=self.copy_seed_to_clipboard)
        # Initially hidden unless lazy mode
        if self.lazy_mode:
            self.copy_btn.pack(pady=(5, 0))

        # Instructions
        tk.Label(content, text="1. Write down all words in order on paper",
                 font=('Segoe UI', 10), fg=self.fg, bg=self.bg).pack(anchor=tk.W, pady=(5, 2))
        tk.Label(content, text="2. Store the paper in a safe place",
                 font=('Segoe UI', 10), fg=self.fg, bg=self.bg).pack(anchor=tk.W, pady=2)
        tk.Label(content, text="3. Click 'Continue' to proceed",
                 font=('Segoe UI', 10), fg=self.fg, bg=self.bg).pack(anchor=tk.W, pady=2)

        # Buttons
        btn_frame = tk.Frame(content, bg=self.bg)
        btn_frame.pack(fill=tk.X, pady=(20, 0))

        self.continue_btn = tk.Button(btn_frame, text="I've Written It Down →", 
                                      font=('Segoe UI', 11, 'bold'),
                                      bg=self.accent_green, fg='#fff', relief=tk.FLAT, padx=20, pady=10,
                                      command=self.on_continue)
        self.continue_btn.pack(side=tk.LEFT, padx=(0, 10))

        tk.Button(btn_frame, text="🔄 Generate New", font=('Segoe UI', 10),
                  bg=self.bg_card, fg=self.fg_dim, relief=tk.FLAT, padx=15, pady=10,
                  command=self.create_step1).pack(side=tk.LEFT, padx=(0, 10))

        tk.Button(btn_frame, text="Cancel", font=('Segoe UI', 10),
                  bg=self.bg_card, fg=self.fg_dim, relief=tk.FLAT, padx=15, pady=10,
                  command=self.on_close).pack(side=tk.LEFT)
    
    def on_word_count_change(self):
        """Handle word count change"""
        new_wc = self.wc_var.get()
        if new_wc != self.word_count:
            self.word_count = new_wc
            self.create_step1()  # Regenerate with new word count
    
    def on_lazy_toggle(self):
        """Handle lazy mode toggle"""
        self.lazy_mode = self.lazy_var.get()
        
        # Show/hide copy button
        if self.lazy_mode:
            self.copy_btn.pack(pady=(5, 0))
            self.continue_btn.config(text="Skip Verification & Create →")
        else:
            self.copy_btn.pack_forget()
            self.continue_btn.config(text="I've Written It Down →")
    
    def copy_seed_to_clipboard(self):
        """Copy seed phrase to clipboard (lazy mode only)"""
        if self.mnemonic and self.lazy_mode:
            self.top.clipboard_clear()
            self.top.clipboard_append(self.mnemonic)
            
            # Visual feedback
            orig_text = self.copy_btn.cget('text')
            self.copy_btn.config(text="✓ Copied!", bg='#27ae60')
            self.top.after(2000, lambda: self.copy_btn.config(text=orig_text, bg=self.accent_yolo))
    
    def on_continue(self):
        """Handle continue button - either verify or skip"""
        if self.lazy_mode:
            # Skip verification, go straight to wallet creation
            self.top.destroy()
            self.gui.finalize_wallet_from_seed(self.mnemonic, self.keyid)
        else:
            # Go to verification step
            self.create_step2()

    def create_step2(self):
        """Step 2: Verify seed phrase"""
        # Clear window
        for widget in self.top.winfo_children():
            widget.destroy()

        content = tk.Frame(self.top, bg=self.bg, padx=30, pady=25)
        content.pack(fill=tk.BOTH, expand=True)

        # Title
        tk.Label(content, text="VERIFY YOUR SEED PHRASE", font=('Segoe UI', 16, 'bold'),
                 fg=self.accent, bg=self.bg).pack(anchor=tk.W, pady=(0, 5))

        tk.Label(content, text="Enter your seed phrase to confirm you wrote it down correctly.",
                 font=('Segoe UI', 10), fg=self.fg_dim, bg=self.bg).pack(anchor=tk.W, pady=(0, 20))

        # Input area
        tk.Label(content, text=f"Enter all {self.word_count} words separated by spaces:",
                 font=('Segoe UI', 10), fg=self.fg, bg=self.bg).pack(anchor=tk.W, pady=(0, 10))

        self.verify_text = tk.Text(content, height=4, font=('Consolas', 12),
                                    bg=self.bg_input, fg=self.fg, relief=tk.FLAT,
                                    padx=15, pady=15, insertbackground='#fff')
        self.verify_text.pack(fill=tk.X, pady=(0, 15))

        # Status
        self.verify_status = tk.Label(content, text="", font=('Segoe UI', 10),
                                       fg=self.fg_dim, bg=self.bg)
        self.verify_status.pack(anchor=tk.W, pady=(0, 20))

        # Buttons
        btn_frame = tk.Frame(content, bg=self.bg)
        btn_frame.pack(fill=tk.X, pady=(10, 0))

        tk.Button(btn_frame, text="Verify & Create Wallet", font=('Segoe UI', 11, 'bold'),
                  bg=self.accent_green, fg='#fff', relief=tk.FLAT, padx=20, pady=10,
                  command=self.verify_and_create).pack(side=tk.LEFT, padx=(0, 10))

        tk.Button(btn_frame, text="Go Back", font=('Segoe UI', 10),
                  bg=self.bg_card, fg=self.fg_dim, relief=tk.FLAT, padx=15, pady=10,
                  command=self.create_step1).pack(side=tk.LEFT, padx=(0, 10))

        tk.Button(btn_frame, text="Cancel", font=('Segoe UI', 10),
                  bg=self.bg_card, fg=self.fg_dim, relief=tk.FLAT, padx=15, pady=10,
                  command=self.on_close).pack(side=tk.LEFT)

    def verify_and_create(self):
        """Verify entered seed matches and create wallet"""
        entered = self.verify_text.get("1.0", tk.END).strip().lower()
        entered_words = entered.split()

        if len(entered_words) != self.word_count:
            self.verify_status.config(
                text=f"Please enter exactly {self.word_count} words (you entered {len(entered_words)})",
                fg='#e74c3c')
            return

        if entered != self.mnemonic.lower():
            self.verify_status.config(text="Seed phrase does not match! Check your spelling and order.",
                                       fg='#e74c3c')
            return

        # Success - create wallet
        self.verify_status.config(text="Seed phrase verified! Creating wallet...", fg=self.accent_green)
        self.top.destroy()
        self.gui.finalize_wallet_from_seed(self.mnemonic, self.keyid)


class ImportWalletDialog:
    """Dialog for importing wallet from existing seed phrase"""

    def __init__(self, parent, gui, keyid):
        self.gui = gui
        self.keyid = keyid

        # Colors
        self.bg = '#0f0f1a'
        self.bg_card = '#1a1a2e'
        self.bg_input = '#252540'
        self.fg = '#e8e8e8'
        self.fg_dim = '#888'
        self.accent = '#3498db'
        self.accent_green = '#27ae60'

        self.top = tk.Toplevel(parent)
        self.top.title("Import Wallet from Seed")
        self.top.geometry("600x500")
        self.top.configure(bg=self.bg)
        self.top.transient(parent)
        self.top.grab_set()

        self.create_ui()

    def create_ui(self):
        content = tk.Frame(self.top, bg=self.bg, padx=30, pady=25)
        content.pack(fill=tk.BOTH, expand=True)

        # Title
        tk.Label(content, text="IMPORT WALLET FROM SEED PHRASE", font=('Segoe UI', 16, 'bold'),
                 fg=self.accent, bg=self.bg).pack(anchor=tk.W, pady=(0, 5))

        tk.Label(content, text="Enter your 12 or 24 word seed phrase to restore your wallet.",
                 font=('Segoe UI', 10), fg=self.fg_dim, bg=self.bg).pack(anchor=tk.W, pady=(0, 20))

        # Info
        info_frame = tk.Frame(content, bg=self.bg_card, padx=15, pady=12)
        info_frame.pack(fill=tk.X, pady=(0, 20))
        tk.Label(info_frame, text="This will derive your private key and write it to the SE050.",
                 font=('Segoe UI', 9), fg=self.fg_dim, bg=self.bg_card).pack(anchor=tk.W)
        tk.Label(info_frame, text=f"Target key slot: 0x{self.keyid}",
                 font=('Segoe UI', 9, 'bold'), fg=self.accent, bg=self.bg_card).pack(anchor=tk.W)

        # Input area
        tk.Label(content, text="Enter your seed phrase (12 or 24 words):",
                 font=('Segoe UI', 10), fg=self.fg, bg=self.bg).pack(anchor=tk.W, pady=(0, 10))

        self.seed_text = tk.Text(content, height=5, font=('Consolas', 12),
                                  bg=self.bg_input, fg=self.fg, relief=tk.FLAT,
                                  padx=15, pady=15, insertbackground='#fff')
        self.seed_text.pack(fill=tk.X, pady=(0, 10))

        # Validation status
        self.status_label = tk.Label(content, text="", font=('Segoe UI', 10),
                                      fg=self.fg_dim, bg=self.bg)
        self.status_label.pack(anchor=tk.W, pady=(0, 20))

        # Validate button
        tk.Button(content, text="Validate Seed Phrase", font=('Segoe UI', 10),
                  bg=self.bg_card, fg=self.fg, relief=tk.FLAT, padx=15, pady=8,
                  command=self.validate_seed).pack(anchor=tk.W, pady=(0, 20))

        # Buttons
        btn_frame = tk.Frame(content, bg=self.bg)
        btn_frame.pack(fill=tk.X, pady=(10, 0))

        self.import_btn = tk.Button(btn_frame, text="Import Wallet", font=('Segoe UI', 11, 'bold'),
                                     bg=self.accent_green, fg='#fff', relief=tk.FLAT, padx=20, pady=10,
                                     command=self.import_wallet, state='disabled')
        self.import_btn.pack(side=tk.LEFT, padx=(0, 10))

        tk.Button(btn_frame, text="Cancel", font=('Segoe UI', 10),
                  bg=self.bg_card, fg=self.fg_dim, relief=tk.FLAT, padx=15, pady=10,
                  command=self.top.destroy).pack(side=tk.LEFT)

    def validate_seed(self):
        """Validate the entered seed phrase"""
        mnemonic = self.seed_text.get("1.0", tk.END).strip().lower()
        words = mnemonic.split()

        if len(words) not in (12, 15, 18, 21, 24):
            self.status_label.config(text=f"Invalid word count: {len(words)} (need 12 or 24)", fg='#e74c3c')
            self.import_btn.config(state='disabled')
            return

        if validate_mnemonic(mnemonic):
            self.status_label.config(text=f"Valid {len(words)}-word seed phrase!", fg=self.accent_green)
            self.import_btn.config(state='normal')
        else:
            self.status_label.config(text="Invalid seed phrase - check spelling and word order", fg='#e74c3c')
            self.import_btn.config(state='disabled')

    def import_wallet(self):
        """Import the wallet from seed phrase"""
        mnemonic = self.seed_text.get("1.0", tk.END).strip().lower()

        if not validate_mnemonic(mnemonic):
            messagebox.showerror("Error", "Invalid seed phrase")
            return

        self.status_label.config(text="Importing wallet...", fg=self.accent)
        self.top.destroy()
        self.gui.finalize_wallet_from_seed(mnemonic, self.keyid)


def main():
    # Parse args
    if '--testnet' in sys.argv:
        Config.NETWORK = "testnet"
    
    if '--keyid' in sys.argv:
        idx = sys.argv.index('--keyid')
        if idx + 1 < len(sys.argv):
            Config.KEY_ID = sys.argv[idx + 1]
    
    # Show backend info
    print(f"SE050ARD Wallet GUI")
    print(f"  Backend: {SE050_BACKEND}")
    print(f"  Native C library: {'available' if is_native_available() else 'not found (using ssscli)'}")
    print(f"  Network: {Config.NETWORK}")
    print()
    
    # Pre-check: try to connect to SE050 before launching GUI
    port = Config.get_connection_port()
    print(f"Connecting to SE050 via {Config.CONNECTION_TYPE} @ {port}...")
    
    if not se050_connect(debug=True):
        print("ERROR: Cannot connect to SE050!")
        print("")
        print("Check:")
        print("  1. K64F is connected via USB")
        print("  2. SE050ARD is attached to K64F")
        print("  3. Device exists: ls /dev/ttyACM*")
        print("")
        print(f"Try manually: ssscli connect se05x vcom {port}")
        print("              ssscli se05x uid")
        sys.exit(1)
    print("SE050 connected!")
    
    root = tk.Tk()
    app = WalletGUI(root)
    root.mainloop()


if __name__ == '__main__':
    main()

