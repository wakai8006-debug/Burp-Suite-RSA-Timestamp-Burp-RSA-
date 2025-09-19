# -*- coding: utf-8 -*-
# rsa_ts_generator_ui_fixed.py
# Burp Jython extension — RSA timestamp payload generator with UI (dynamic public key, § removed)

from burp import IBurpExtender, IIntruderPayloadGeneratorFactory, IIntruderPayloadGenerator, ITab
from java.util import Base64
from javax.crypto import Cipher
from java.security import KeyFactory
from java.security.spec import X509EncodedKeySpec
from javax.swing import (JPanel, JLabel, JButton, JTextArea, JScrollPane,
                         JCheckBox, JRadioButton, ButtonGroup, JTextField)
from java.awt import BorderLayout, Dimension, FlowLayout
import time, threading, traceback

# Default UI values
DEFAULT_MS = True
DEFAULT_LIMIT = 0
GENERATOR_NAME = "rsa-ts-generator-ui"

class BurpExtender(IBurpExtender, IIntruderPayloadGeneratorFactory, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("RSA Timestamp Payload Generator (UI)")
        callbacks.registerIntruderPayloadGeneratorFactory(self)

        # Shared state
        self.state = {
            "public_pem": "",
            "ms": DEFAULT_MS,
            "limit": DEFAULT_LIMIT
        }

        # Create UI
        self._create_ui(callbacks)
        callbacks.addSuiteTab(self)

        print("[+] RSA Timestamp Payload Generator (UI) registered")

    # ITab methods
    def getTabCaption(self):
        return "RSA-ts-gen"

    def getUiComponent(self):
        return self.panel

    # IIntruderPayloadGeneratorFactory
    def getGeneratorName(self):
        return GENERATOR_NAME

    def createNewInstance(self, attack):
        return RsaTimestampGeneratorUI(self.state)

    # UI creation
    def _create_ui(self, callbacks):
        self.panel = JPanel(BorderLayout())
        top = JPanel(BorderLayout())

        label = JLabel("Public Key (PEM) - paste here:")
        top.add(label, BorderLayout.NORTH)

        self.textarea = JTextArea()
        self.textarea.setLineWrap(False)
        self.textarea.setEditable(True)
        scroll = JScrollPane(self.textarea)
        scroll.setPreferredSize(Dimension(600, 200))
        top.add(scroll, BorderLayout.CENTER)

        ctrl = JPanel(FlowLayout(FlowLayout.LEFT))

        self.ms_rb = JRadioButton("Milliseconds (13-digit)", DEFAULT_MS)
        self.s_rb = JRadioButton("Seconds (10-digit)", not DEFAULT_MS)
        bg = ButtonGroup()
        bg.add(self.ms_rb)
        bg.add(self.s_rb)
        ctrl.add(self.ms_rb)
        ctrl.add(self.s_rb)

        ctrl.add(JLabel("Payload limit (0=unlimited):"))
        self.limit_field = JTextField(str(DEFAULT_LIMIT))
        self.limit_field.setColumns(6)
        ctrl.add(self.limit_field)

        top.add(ctrl, BorderLayout.SOUTH)

        bottom = JPanel(FlowLayout(FlowLayout.LEFT))
        self.save_btn = JButton("Save Settings", actionPerformed=self.save_settings)
        bottom.add(self.save_btn)
        self.status_lbl = JLabel("Status: no public key set")
        bottom.add(self.status_lbl)

        self.panel.add(top, BorderLayout.CENTER)
        self.panel.add(bottom, BorderLayout.SOUTH)

    def save_settings(self, event):
        pem = self.textarea.getText().strip()
        ms = bool(self.ms_rb.isSelected())
        try:
            limit = int(self.limit_field.getText().strip())
            if limit < 0:
                limit = 0
        except:
            limit = 0

        self.state["public_pem"] = pem
        self.state["ms"] = ms
        self.state["limit"] = limit

        if pem and "BEGIN PUBLIC KEY" in pem:
            self.status_lbl.setText("Status: public key set, ready")
            print("[*] RSA public key updated (UI). ms=%s limit=%s" % (ms, limit))
        elif not pem:
            self.status_lbl.setText("Status: public key cleared")
            print("[*] RSA public key cleared (UI).")
        else:
            self.status_lbl.setText("Status: invalid PEM (must contain BEGIN PUBLIC KEY)")
            print("[!] Saved public key seems invalid (missing header/footer)")

class RsaTimestampGeneratorUI(IIntruderPayloadGenerator):
    def __init__(self, state):
        self._stopped = False
        self._count = 0
        self._lock = threading.Lock()
        self.state = state
        self._pubkey_obj = None
        self._cipher = None
        self._current_pub_pem = None

    def _ensure_key(self):
        pem = self.state.get("public_pem", "").strip()
        if pem == "":
            self._pubkey_obj = None
            self._cipher = None
            self._current_pub_pem = None
            return False

        if pem == self._current_pub_pem and self._pubkey_obj is not None:
            return True

        try:
            header = "-----BEGIN PUBLIC KEY-----"
            footer = "-----END PUBLIC KEY-----"
            body = pem.replace(header, "").replace(footer, "").replace("\r", "").replace("\n", "").strip()
            key_bytes = Base64.getDecoder().decode(body)
            spec = X509EncodedKeySpec(key_bytes)
            kf = KeyFactory.getInstance("RSA")
            self._pubkey_obj = kf.generatePublic(spec)
            self._cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
            self._current_pub_pem = pem
            print("[*] Loaded public key for generator")
            return True
        except Exception as e:
            print("[!] Error parsing public key:", e)
            traceback.print_exc()
            self._pubkey_obj = None
            self._cipher = None
            self._current_pub_pem = None
            return False

    def hasMorePayloads(self):
        limit = int(self.state.get("limit") or 0)
        if limit and self._count >= limit:
            return False
        return not self._stopped

    def getNextPayload(self, baseValue):
        with self._lock:
            if self._stopped:
                return ""
            if not self._ensure_key():
                return ""

            try:
                ms_flag = bool(self.state.get("ms", True))
                if ms_flag:
                    ts = int(time.time() * 1000)
                else:
                    ts = int(time.time())
                plaintext = str(ts).encode("utf-8")

                self._cipher.init(Cipher.ENCRYPT_MODE, self._pubkey_obj)
                enc = self._cipher.doFinal(plaintext)
                b64 = Base64.getEncoder().encodeToString(enc)

                # § removed, direct Base64 output
                payload = b64

                self._count += 1
                return payload
            except Exception as ex:
                print("[!] Error generating payload:", ex)
                traceback.print_exc()
                return ""

    def reset(self):
        with self._lock:
            self._stopped = False
            self._count = 0
        return
