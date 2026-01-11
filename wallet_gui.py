#!/usr/bin/env python3
"""
SE050ARD Hardware Bitcoin Wallet - GUI
======================================

Tkinter GUI for the SE050 hardware wallet.
Designed to work over VNC.

Usage:
    ./wallet_gui.py
    ./wallet_gui.py --testnet

Author: _SiCk @ afflicted.sh
License: MIT
"""

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, scrolledtext
import threading
import sys
import os

# Import wallet functions
from wallet import (
    Config, Wallet, 
    se050_connect, se050_key_exists, se050_sign, se050_get_uid, se050_get_random,
    se050_generate_keypair, se050_export_pubkey, se050_delete_key,
    get_utxos, get_address_info, get_fee_estimates, get_btc_price, get_address_txs,
    format_timestamp, build_and_sign_transaction, create_output_script, api_post,
    sign_message_with_se050, encode_signed_message,
    generate_qr_ascii, hash160, sha256, parse_amount
)
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
        self.root.geometry("800x600")
        self.root.configure(bg='#1a1a2e')
        
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
        
        # Build UI
        self.create_widgets()
        
        # Initial load
        self.root.after(100, self.initial_load)
    
    def configure_styles(self):
        """Configure ttk styles for dark theme"""
        self.style.configure('TFrame', background='#1a1a2e')
        self.style.configure('TLabel', background='#1a1a2e', foreground='#eee', font=('Consolas', 10))
        self.style.configure('Title.TLabel', font=('Consolas', 14, 'bold'), foreground='#f39c12')
        self.style.configure('Address.TLabel', font=('Consolas', 9), foreground='#3498db')
        self.style.configure('Balance.TLabel', font=('Consolas', 24, 'bold'), foreground='#2ecc71')
        self.style.configure('TButton', font=('Consolas', 10), padding=10)
        self.style.configure('Status.TLabel', font=('Consolas', 9), foreground='#888')
        
    def create_widgets(self):
        """Create all UI widgets"""
        # Main container
        self.main_frame = ttk.Frame(self.root, padding=20)
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Header
        header_frame = ttk.Frame(self.main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 20))
        
        ttk.Label(header_frame, text="SE050ARD HARDWARE WALLET", style='Title.TLabel').pack(side=tk.LEFT)
        
        network_text = f"[{Config.NETWORK.upper()}]"
        self.network_label = ttk.Label(header_frame, text=network_text, foreground='#e74c3c' if Config.NETWORK == 'mainnet' else '#f39c12')
        self.network_label.pack(side=tk.RIGHT)
        
        # Connection status
        self.status_frame = ttk.Frame(self.main_frame)
        self.status_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.status_indicator = tk.Canvas(self.status_frame, width=12, height=12, bg='#1a1a2e', highlightthickness=0)
        self.status_indicator.pack(side=tk.LEFT, padx=(0, 5))
        self.status_dot = self.status_indicator.create_oval(2, 2, 10, 10, fill='#666')
        
        self.status_label = ttk.Label(self.status_frame, text="Connecting...", style='Status.TLabel')
        self.status_label.pack(side=tk.LEFT)
        
        # Content area - two columns
        content_frame = ttk.Frame(self.main_frame)
        content_frame.pack(fill=tk.BOTH, expand=True)
        
        # Left column - wallet info
        left_frame = ttk.Frame(content_frame)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        # Balance
        balance_frame = ttk.Frame(left_frame)
        balance_frame.pack(fill=tk.X, pady=(0, 20))
        
        ttk.Label(balance_frame, text="BALANCE").pack(anchor=tk.W)
        self.balance_label = ttk.Label(balance_frame, text="--- sats", style='Balance.TLabel')
        self.balance_label.pack(anchor=tk.W)
        self.fiat_label = ttk.Label(balance_frame, text="", style='Status.TLabel')
        self.fiat_label.pack(anchor=tk.W)
        
        # Addresses
        addr_frame = ttk.Frame(left_frame)
        addr_frame.pack(fill=tk.X, pady=(0, 20))
        
        ttk.Label(addr_frame, text="SEGWIT ADDRESS (recommended)").pack(anchor=tk.W)
        self.segwit_var = tk.StringVar(value="---")
        segwit_entry = ttk.Entry(addr_frame, textvariable=self.segwit_var, font=('Consolas', 9), width=50, state='readonly')
        segwit_entry.pack(fill=tk.X, pady=(2, 5))
        
        ttk.Label(addr_frame, text="LEGACY ADDRESS").pack(anchor=tk.W)
        self.legacy_var = tk.StringVar(value="---")
        legacy_entry = ttk.Entry(addr_frame, textvariable=self.legacy_var, font=('Consolas', 9), width=50, state='readonly')
        legacy_entry.pack(fill=tk.X, pady=(2, 5))
        
        # Copy buttons
        copy_frame = ttk.Frame(addr_frame)
        copy_frame.pack(fill=tk.X, pady=(5, 0))
        ttk.Button(copy_frame, text="📋 Copy SegWit", command=self.copy_segwit).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(copy_frame, text="📋 Copy Legacy", command=self.copy_legacy).pack(side=tk.LEFT)
        
        # Right column - QR code
        right_frame = ttk.Frame(content_frame, width=200)
        right_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=(10, 0))
        right_frame.pack_propagate(False)
        
        ttk.Label(right_frame, text="SCAN TO RECEIVE").pack(anchor=tk.CENTER)
        
        self.qr_canvas = tk.Canvas(right_frame, width=180, height=180, bg='white', highlightthickness=1, highlightbackground='#333')
        self.qr_canvas.pack(pady=10)
        self.qr_canvas.create_text(90, 90, text="No wallet", fill='#999')
        
        # Action buttons
        button_frame = ttk.Frame(self.main_frame)
        button_frame.pack(fill=tk.X, pady=(20, 10))
        
        ttk.Button(button_frame, text="🔄 Refresh", command=self.refresh_balance).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame, text="📤 Send", command=self.show_send_dialog).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame, text="✍️ Sign Message", command=self.show_sign_dialog).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame, text="📜 History", command=self.show_history).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame, text="✓ Verify", command=self.verify_se050).pack(side=tk.LEFT, padx=(0, 5))
        
        # Monitor toggle
        self.monitor_btn = ttk.Button(button_frame, text="👁 Monitor", command=self.toggle_monitor)
        self.monitor_btn.pack(side=tk.RIGHT, padx=(5, 0))
        
        self.monitor_label = ttk.Label(button_frame, text="", style='Status.TLabel')
        self.monitor_label.pack(side=tk.RIGHT, padx=(5, 0))
        
        # Bottom status bar
        self.bottom_status = ttk.Label(self.main_frame, text="", style='Status.TLabel')
        self.bottom_status.pack(fill=tk.X, pady=(10, 0))
        
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
                    self.root.after(0, self.refresh_balance)
                else:
                    self.root.after(0, lambda: self.set_status("No wallet found - use CLI to init", 'orange'))
            else:
                self.root.after(0, lambda: self.set_status("SE050 Connection Failed", 'red'))
        except Exception as e:
            self.root.after(0, lambda: self.set_status(f"Error: {e}", 'red'))
    
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
                qr = qrcode.QRCode(version=1, box_size=4, border=2)
                qr.add_data(addr)
                qr.make(fit=True)
                img = qr.make_image(fill_color="black", back_color="white")
                img = img.resize((176, 176), Image.NEAREST)
                self.qr_image = ImageTk.PhotoImage(img)
                self.qr_canvas.delete("all")
                self.qr_canvas.create_image(90, 90, image=self.qr_image)
            except Exception as e:
                self.qr_canvas.delete("all")
                self.qr_canvas.create_text(90, 90, text=f"QR Error:\n{e}", fill='red', width=160)
        else:
            self.qr_canvas.delete("all")
            self.qr_canvas.create_text(90, 90, text="Install qrcode+pillow\nfor QR display", fill='#666', width=160)
    
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
            self.root.after(0, lambda: self.bottom_status.config(text=f"Error: {e}"))
    
    def _update_balance_display(self):
        """Update balance labels"""
        self.balance_label.config(text=f"{self.balance_sats:,} sats")
        
        if self.btc_price and self.balance_sats > 0:
            fiat = (self.balance_sats / 1e8) * self.btc_price
            self.fiat_label.config(text=f"≈ ${fiat:,.2f} USD @ ${self.btc_price:,.0f}")
        else:
            self.fiat_label.config(text=f"{self.balance_sats / 1e8:.8f} BTC")
        
        fees = get_fee_estimates()
        self.bottom_status.config(text=f"Fees: {fees.get('fastestFee', '?')} sat/vB (fast) | {fees.get('hourFee', '?')} sat/vB (slow)")
    
    def toggle_monitor(self):
        """Toggle balance monitoring on/off"""
        if self.monitoring:
            self.monitoring = False
            self.monitor_btn.config(text="👁 Monitor")
            self.monitor_label.config(text="")
            self.bottom_status.config(text="Monitoring stopped")
        else:
            self.monitoring = True
            self.last_balance = self.balance_sats
            self.monitor_btn.config(text="⏹ Stop")
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
            self.root.after(0, lambda: self.bottom_status.config(text=f"Monitor error: {e}"))
    
    def _notify_balance_change(self, diff_sats):
        """Notify user of balance change"""
        self.last_balance = self.balance_sats
        
        if diff_sats > 0:
            msg = f"💰 RECEIVED +{diff_sats:,} sats!"
            self.balance_label.config(foreground='#27ae60')  # Bright green
        else:
            msg = f"📤 SENT {diff_sats:,} sats"
            self.balance_label.config(foreground='#e74c3c')  # Red
        
        self.bottom_status.config(text=msg)
        
        # Flash the window title
        self.root.title(msg)
        self.root.after(3000, lambda: self.root.title("SE050ARD Bitcoin Wallet"))
        
        # Reset balance color after delay
        self.root.after(5000, lambda: self.balance_label.config(foreground='#2ecc71'))
        
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
            self.root.after(0, lambda: messagebox.showerror("Error", f"Signing failed: {e}"))
    
    def _show_signature_result(self, message, signature):
        """Show signed message result"""
        result_window = tk.Toplevel(self.root)
        result_window.title("Signed Message")
        result_window.geometry("500x300")
        result_window.configure(bg='#1a1a2e')
        
        frame = ttk.Frame(result_window, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text="MESSAGE:").pack(anchor=tk.W)
        msg_text = scrolledtext.ScrolledText(frame, height=3, font=('Consolas', 9))
        msg_text.insert(tk.END, message)
        msg_text.config(state='disabled')
        msg_text.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(frame, text="ADDRESS:").pack(anchor=tk.W)
        ttk.Label(frame, text=self.wallet.addresses['legacy'], style='Address.TLabel').pack(anchor=tk.W, pady=(0, 10))
        
        ttk.Label(frame, text="SIGNATURE:").pack(anchor=tk.W)
        sig_text = scrolledtext.ScrolledText(frame, height=3, font=('Consolas', 9))
        sig_text.insert(tk.END, signature)
        sig_text.config(state='disabled')
        sig_text.pack(fill=tk.X, pady=(0, 10))
        
        def copy_sig():
            self.root.clipboard_clear()
            self.root.clipboard_append(signature)
        
        ttk.Button(frame, text="📋 Copy Signature", command=copy_sig).pack()
        
        self.bottom_status.config(text="Message signed!")
    
    def show_history(self):
        """Show transaction history"""
        if not self.wallet.addresses:
            messagebox.showerror("Error", "No wallet loaded")
            return
        
        hist_window = tk.Toplevel(self.root)
        hist_window.title("Transaction History")
        hist_window.geometry("700x400")
        hist_window.configure(bg='#1a1a2e')
        
        frame = ttk.Frame(hist_window, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text="TRANSACTION HISTORY", style='Title.TLabel').pack(anchor=tk.W, pady=(0, 10))
        
        # Treeview for transactions
        columns = ('date', 'type', 'amount', 'txid')
        tree = ttk.Treeview(frame, columns=columns, show='headings', height=15)
        tree.heading('date', text='Date')
        tree.heading('type', text='Type')
        tree.heading('amount', text='Amount (sats)')
        tree.heading('txid', text='TXID')
        tree.column('date', width=120)
        tree.column('type', width=60)
        tree.column('amount', width=120)
        tree.column('txid', width=380)
        tree.pack(fill=tk.BOTH, expand=True)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscroll=scrollbar.set)
        
        # Fetch history
        threading.Thread(target=lambda: self._fetch_history(tree), daemon=True).start()
    
    def _fetch_history(self, tree):
        """Background thread: fetch transaction history"""
        try:
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
            
            for tx in unique[:20]:
                status = tx.get('status', {})
                block_time = status.get('block_time', 0)
                date_str = format_timestamp(block_time) if block_time else "Unconfirmed"
                
                # Calculate net
                total_in = sum(v.get('value', 0) for v in tx.get('vout', []) if v.get('scriptpubkey_address') in our_addresses)
                total_out = sum(vin.get('prevout', {}).get('value', 0) for vin in tx.get('vin', []) if vin.get('prevout', {}).get('scriptpubkey_address') in our_addresses)
                net = total_in - total_out
                
                tx_type = "RECV" if net > 0 else "SEND" if net < 0 else "SELF"
                
                self.root.after(0, lambda d=date_str, t=tx_type, a=net, txid=tx['txid']: tree.insert('', tk.END, values=(d, t, f"{a:+,}", txid[:24]+"...")))
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to fetch history: {e}"))
    
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
            
            # Test TRNG
            rng = se050_get_random()
            if rng:
                results.append(f"✓ TRNG: {rng.hex()[:16]}...")
            
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
        self.top = tk.Toplevel(parent)
        self.top.title("Send Bitcoin")
        self.top.geometry("550x480")
        self.top.configure(bg='#1a1a2e')
        self.top.transient(parent)
        self.top.grab_set()
        
        # Cache price for consistent calculations
        self.cached_prices = {}
        
        frame = ttk.Frame(self.top, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Destination
        ttk.Label(frame, text="DESTINATION ADDRESS:").pack(anchor=tk.W)
        self.dest_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.dest_var, font=('Consolas', 10), width=60).pack(fill=tk.X, pady=(2, 15))
        
        # Amount with unit selector
        ttk.Label(frame, text="AMOUNT:").pack(anchor=tk.W)
        amount_frame = ttk.Frame(frame)
        amount_frame.pack(fill=tk.X, pady=(2, 5))
        
        self.amount_var = tk.StringVar()
        amount_entry = ttk.Entry(amount_frame, textvariable=self.amount_var, font=('Consolas', 10), width=15)
        amount_entry.pack(side=tk.LEFT)
        amount_entry.bind('<KeyRelease>', lambda e: self.update_calculation())
        
        self.unit_var = tk.StringVar(value="sats")
        unit_combo = ttk.Combobox(amount_frame, textvariable=self.unit_var, values=["sats", "BTC", "USD", "EUR", "GBP"], width=6, state='readonly')
        unit_combo.pack(side=tk.LEFT, padx=(5, 0))
        unit_combo.bind('<<ComboboxSelected>>', lambda e: self.update_calculation())
        
        ttk.Button(amount_frame, text="MAX", command=self.set_max_amount, width=5).pack(side=tk.LEFT, padx=(10, 0))
        
        # Fee rate
        fee_frame = ttk.Frame(frame)
        fee_frame.pack(fill=tk.X, pady=(10, 5))
        
        fees = get_fee_estimates()
        ttk.Label(fee_frame, text="FEE RATE (sat/vB):").pack(side=tk.LEFT)
        self.fee_var = tk.StringVar(value=str(fees.get('halfHourFee', 10)))
        fee_entry = ttk.Entry(fee_frame, textvariable=self.fee_var, font=('Consolas', 10), width=6)
        fee_entry.pack(side=tk.LEFT, padx=(5, 10))
        fee_entry.bind('<KeyRelease>', lambda e: self.update_calculation())
        
        ttk.Label(fee_frame, text=f"(fast: {fees.get('fastestFee', '?')}, slow: {fees.get('hourFee', '?')})", style='Status.TLabel').pack(side=tk.LEFT)
        
        # Calculation breakdown
        calc_frame = ttk.Frame(frame)
        calc_frame.pack(fill=tk.X, pady=(15, 10))
        
        ttk.Label(calc_frame, text="TRANSACTION BREAKDOWN:", style='Title.TLabel').pack(anchor=tk.W)
        
        self.calc_text = tk.Text(calc_frame, height=8, font=('Consolas', 9), bg='#0d0d1a', fg='#aaa', 
                                  relief=tk.FLAT, padx=10, pady=10)
        self.calc_text.pack(fill=tk.X, pady=(5, 0))
        self.calc_text.config(state='disabled')
        
        # Buttons
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, pady=(15, 0))
        
        self.send_btn = ttk.Button(btn_frame, text="Send", command=self.send)
        self.send_btn.pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(btn_frame, text="Cancel", command=self.top.destroy).pack(side=tk.LEFT)
        
        self.status_label = ttk.Label(frame, text="", style='Status.TLabel')
        self.status_label.pack(anchor=tk.W, pady=(10, 0))
        
        # Initial calculation
        self.update_calculation()
    
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
        lines.append(f"  Available:    {self.sats_to_unit(balance_sats, unit)}")
        lines.append(f"")
        lines.append(f"  Send amount:  {self.sats_to_unit(amount_sats, unit)}")
        lines.append(f"  Network fee:  {self.sats_to_unit(fee_sats, unit)} (~{est_vsize} vB × {fee_rate} sat/vB)")
        lines.append(f"  ────────────────────────────────")
        lines.append(f"  Total needed: {self.sats_to_unit(total_needed, unit)}")
        lines.append(f"  Change back:  {self.sats_to_unit(change_sats, unit)}")
        
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
        """Set amount to max available (minus fee)"""
        try:
            fee_rate = int(self.fee_var.get().strip())
        except:
            fee_rate = 10
        
        # Estimate fee for typical tx
        est_vsize = 150  # Conservative estimate
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
        
        amount_sats = self.get_amount_sats()
        if amount_sats <= 0:
            messagebox.showerror("Error", "Enter a valid amount")
            return
        
        try:
            fee_rate = int(self.fee_var.get().strip())
        except:
            messagebox.showerror("Error", "Invalid fee rate")
            return
        
        unit = self.unit_var.get()
        
        # Build confirmation message
        est_vsize = 150
        fee_sats = est_vsize * fee_rate
        total = amount_sats + fee_sats
        
        msg = f"CONFIRM TRANSACTION\n\n"
        msg += f"Send:  {self.sats_to_unit(amount_sats, unit)}\n"
        msg += f"Fee:   {self.sats_to_unit(fee_sats, unit)}\n"
        msg += f"Total: {self.sats_to_unit(total, unit)}\n\n"
        msg += f"To: {dest[:20]}...{dest[-8:]}\n\n"
        msg += f"Proceed?"
        
        if not messagebox.askyesno("Confirm Send", msg):
            return
        
        self.status_label.config(text="Building transaction...")
        self.send_btn.config(state='disabled')
        threading.Thread(target=lambda: self._execute_send(dest, amount_sats, fee_rate), daemon=True).start()
    
    def _execute_send(self, dest, amount_sats, fee_rate):
        """Background thread: execute send"""
        try:
            wallet = self.gui.wallet
            
            # Connect
            if not se050_connect():
                self.top.after(0, lambda: messagebox.showerror("Error", "SE050 connection failed"))
                return
            
            # Get UTXOs
            utxos = get_utxos(wallet.addresses['segwit'])
            if not utxos:
                utxos = get_utxos(wallet.addresses['legacy'])
            
            if not utxos:
                self.top.after(0, lambda: messagebox.showerror("Error", "No UTXOs available"))
                return
            
            total_in = sum(u['value'] for u in utxos)
            est_vsize = 110 + (68 * len(utxos))
            fee = est_vsize * fee_rate
            
            unit = self.unit_var.get()
            
            if total_in < amount_sats + fee:
                shortfall = (amount_sats + fee) - total_in
                msg = f"Insufficient funds\n\nHave: {self.sats_to_unit(total_in, unit)}\nNeed: {self.sats_to_unit(amount_sats + fee, unit)}\nShort: {self.sats_to_unit(shortfall, unit)}"
                self.top.after(0, lambda: messagebox.showerror("Error", msg))
                self.top.after(0, lambda: self.send_btn.config(state='normal'))
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
            raw_tx = build_and_sign_transaction(inputs, outputs, wallet.pubkey_compressed, wallet.pubkey_hash)
            tx_hex = raw_tx.hex()
            
            self.top.after(0, lambda: self.status_label.config(text="Broadcasting..."))
            
            # Broadcast
            txid = api_post("/tx", tx_hex.encode())
            
            if txid:
                self.top.after(0, lambda: self._send_success(txid, amount_sats, fee))
            else:
                self.top.after(0, lambda: messagebox.showerror("Error", "Broadcast failed"))
                self.top.after(0, lambda: self.send_btn.config(state='normal'))
                
        except Exception as e:
            self.top.after(0, lambda: messagebox.showerror("Error", f"Send failed: {e}"))
            self.top.after(0, lambda: self.send_btn.config(state='normal'))
    
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


def main():
    # Parse args
    if '--testnet' in sys.argv:
        Config.NETWORK = "testnet"
    
    if '--keyid' in sys.argv:
        idx = sys.argv.index('--keyid')
        if idx + 1 < len(sys.argv):
            Config.KEY_ID = sys.argv[idx + 1]
    
    # Pre-check: try to connect to SE050 before launching GUI
    print("Connecting to SE050...")
    if not se050_connect():
        print("ERROR: Cannot connect to SE050!")
        print("")
        print("Check:")
        print("  1. K64F is connected via USB")
        print("  2. SE050ARD is attached to K64F")
        print("  3. Device exists: ls /dev/ttyACM*")
        print("")
        print("Try manually: ssscli connect se05x t1oi2c none")
        sys.exit(1)
    print("SE050 connected!")
    
    root = tk.Tk()
    app = WalletGUI(root)
    root.mainloop()


if __name__ == '__main__':
    main()
