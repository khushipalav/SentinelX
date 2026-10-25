
from __future__ import annotations

import csv
import json
import math
import os
import sys
import traceback
from pathlib import Path

from PySide6.QtCore import QObject, QPointF, QRectF, QSize, QTimer, Qt, Signal
from PySide6.QtGui import (
    QColor, QFont, QFontDatabase, QFontMetrics, QGuiApplication, QPainter,
    QIntValidator, QPainterPath, QPen, QPolygonF
)
from PySide6.QtWidgets import (
    QAbstractItemView, QApplication, QCheckBox, QFileDialog, QFormLayout, QFrame,
    QGridLayout, QHBoxLayout, QLabel, QListWidget, QListWidgetItem, QMainWindow,
    QMessageBox, QProgressBar, QPushButton, QScrollArea, QSizePolicy,
    QStackedWidget, QTableWidget, QTableWidgetItem, QLineEdit, QVBoxLayout, QWidget
)

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from malware.detector import scan_file
from phishguard.features import extract_features, is_valid_url
from phishguard.classifier import predict
from phishguard.results import calculate_parameters, normalize_data
from database.database import Database
from sentinelx_core.models import MonitorSettings, ProcessEvent, ProcessInfo, SecurityAlert
from sentinelx_core.process_manager import ProcessManager
from sentinelx_core.process_monitor import ProcessMonitor, SystemSnapshot
from sentinelx_core.security_logger import SecurityLogger
from sentinelx_core.threat_detector import SecurityAnalyzer
from ransomware import (
    Database as RansomwareDB, DetectionEngine, QuarantineManager, scan_folder,
    data_dir as rw_data_dir,
)
from ransomware import Monitor as RansomwareMonitor   # None when 'watchdog' is not installed


# --------------------------------------------------------------------------- #
#  Design tokens
# --------------------------------------------------------------------------- #
INK = "#14162e"        # outlines, hard shadows, primary text
NAVY = "#171b3b"       # dark section
PAGE = "#e8e8ea"       # light section / window background
CREAM = "#f6f4f1"      # soft surfaces
WHITE = "#ffffff"
PURPLE = "#a67de8"     # brand fill
PURPLE_DK = "#8f63da"
LIME = "#d5f26f"       # highlight fill
HEAD_FONT = "Lexend"
BODY_FONT = "Titillium Web"

COLORS = {
    "bg": PAGE,
    "panel": WHITE,
    "panel2": CREAM,
    "border": INK,
    "text": INK,
    "muted": "#5d6078",
    "accent": "#7040c8",     # purple, safe for text on light surfaces
    "accent2": "#2f5fe0",
    "safe": "#14893f",
    "warn": "#b86e00",
    "danger": "#d42a52",
    "critical": "#c01c48",
}

TOKENS = {
    "INK": INK, "NAVY": NAVY, "PAGE": PAGE, "CREAM": CREAM, "WHITE": WHITE,
    "PURPLE": PURPLE, "PURPLE_DK": PURPLE_DK, "LIME": LIME,
    "HEAD": HEAD_FONT, "BODY": BODY_FONT,
    "MUTED": COLORS["muted"], "SAFE": COLORS["safe"], "ACCENT": COLORS["accent"],
}

_QSS = """
QWidget {
    background: transparent; color: @INK@;
    font-family: "@BODY@", "Segoe UI", sans-serif; font-size: 14px;
}
QMainWindow { background: @PAGE@; }
QToolTip { background: @INK@; color: @WHITE@; border: 0; padding: 5px 9px; }
QDialog, QMessageBox, QFileDialog { background: @CREAM@; }
QMessageBox QPushButton, QDialog QPushButton {
    background: @PURPLE@; color: @WHITE@; border: 2px solid @INK@; border-radius: 17px;
    padding: 6px 22px; min-width: 64px; font-family: "@HEAD@"; font-size: 13px;
}
QMessageBox QPushButton:hover, QDialog QPushButton:hover { background: @PURPLE_DK@; }

/* ---- top bar ---- */
QLabel#Brand { font-family: "@HEAD@"; font-size: 28px; font-weight: 700; color: @INK@; }
QLabel#Tag { color: @MUTED@; font-size: 11px; font-family: "@BODY@"; }
QFrame#NavPill { background: #dedee2; border: 2px solid #3a3d52; border-radius: 28px; }
QPushButton#Nav {
    background: transparent; border: 0; border-radius: 22px; padding: 0 20px;
    min-height: 44px; max-height: 44px; color: @INK@;
    font-family: "@HEAD@"; font-size: 14px; font-weight: 400; text-align: center;
}
QPushButton#Nav:hover { background: rgba(20, 22, 46, 0.09); }
QPushButton#Nav:checked { background: @PURPLE@; color: @WHITE@; }

/* ---- type ---- */
QLabel#PageTitle { font-family: "@HEAD@"; font-size: 40px; font-weight: 400; color: @INK@; }
QLabel#HeroTitle { font-family: "@HEAD@"; font-size: 50px; font-weight: 400; color: @INK@; }
QLabel#PageSub { color: @MUTED@; font-size: 15px; }
QLabel#HeroText { color: @INK@; font-size: 15px; }
QLabel#CardTag {
    background: @LIME@; color: @INK@; border-radius: 4px; padding: 5px 14px;
    font-family: "@HEAD@"; font-size: 13px;
}
QLabel#BandTitle { color: @WHITE@; font-family: "@HEAD@"; font-size: 13px; }
QLabel#CardTitle { color: @MUTED@; font-size: 13px; font-weight: 600; }
QLabel#Big { font-family: "@HEAD@"; font-size: 32px; font-weight: 700; }
QLabel#Status { color: @SAFE@; font-family: "@HEAD@"; font-size: 13px; font-weight: 700; }
QLabel#StripLead { font-family: "@HEAD@"; font-size: 16px; color: @MUTED@; }
QLabel#Verdict {
    font-family: "@HEAD@"; font-size: 24px; font-weight: 700; padding: 12px 10px;
    background: transparent; color: @INK@;
}
QLabel#FileField {
    background: @CREAM@; border: 2px dashed @INK@; border-radius: 16px;
    padding: 11px 18px; color: @MUTED@; font-size: 14px;
}
QLabel#Pill {
    background: @WHITE@; color: @SAFE@; border: 2px solid @INK@; border-radius: 16px;
    padding: 6px 16px; font-family: "@HEAD@"; font-size: 12px; font-weight: 700;
}
QFrame#StripDivider { background: rgba(20, 22, 46, 0.22); border: 0; max-width: 1px; min-width: 1px; }

/* ---- inputs ---- */
QLineEdit, QTextEdit {
    background: @WHITE@; border: 2px solid @INK@; border-radius: 22px;
    padding: 10px 18px; selection-background-color: @PURPLE@; selection-color: @WHITE@;
}
QLineEdit:focus, QTextEdit:focus { border: 2px solid @PURPLE_DK@; }

QCheckBox { spacing: 10px; min-height: 28px; }
QCheckBox::indicator { width: 18px; height: 18px; border: 2px solid @INK@; border-radius: 5px; background: @WHITE@; }
QCheckBox::indicator:checked { background: @PURPLE@; }

QProgressBar {
    background: @WHITE@; border: 2px solid @INK@; border-radius: 13px; min-height: 22px;
    max-height: 22px; text-align: center; color: @INK@;
    font-family: "@HEAD@"; font-size: 11px; font-weight: 700;
}
QProgressBar::chunk { background: @PURPLE@; border-radius: 9px; margin: 2px; }

QListWidget {
    background: @CREAM@; border: 2px solid @INK@; border-radius: 14px; padding: 6px; outline: 0;
}
QListWidget::item { padding: 6px 10px; border-radius: 8px; }
QListWidget::item:hover { background: #efe9fb; }
QListWidget::item:selected { background: @LIME@; color: @INK@; }

QTableWidget {
    background: @WHITE@; alternate-background-color: #f5f1fc; border: 0;
    gridline-color: transparent; outline: 0;
    selection-background-color: @LIME@; selection-color: @INK@;
}
QTableWidget::item { padding: 4px 8px; }
QHeaderView { background: transparent; border: 0; }
QHeaderView::section {
    background: @LIME@; color: @INK@; border: 0; border-bottom: 2px solid @INK@;
    padding: 10px 9px; font-family: "@HEAD@"; font-size: 11px; font-weight: 700;
}
QHeaderView::section:first { border-top-left-radius: 12px; }
QHeaderView::section:last { border-top-right-radius: 12px; }
QTableCornerButton::section { background: @LIME@; border: 0; }

QScrollBar:vertical { background: transparent; width: 12px; margin: 3px; }
QScrollBar::handle:vertical { background: @INK@; border-radius: 3px; min-height: 32px; }
QScrollBar:horizontal { background: transparent; height: 12px; margin: 3px; }
QScrollBar::handle:horizontal { background: @INK@; border-radius: 3px; min-width: 32px; }
QScrollBar::add-line, QScrollBar::sub-line { width: 0; height: 0; }
QScrollBar::add-page, QScrollBar::sub-page { background: transparent; }
"""


def _build_style() -> str:
    out = _QSS
    for key, value in TOKENS.items():
        out = out.replace(f"@{key}@", value)
    return out


STYLE = _build_style()


def _font(family: str, px: int, bold: bool = False, spacing: float = 0.0) -> QFont:
    f = QFont(family)
    f.setPixelSize(px)
    f.setBold(bold)
    if spacing:
        f.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, spacing)
    f.setHintingPreference(QFont.HintingPreference.PreferNoHinting)
    return f


def _star(cx: float, cy: float, r: float) -> QPainterPath:
    """Four-point sparkle with concave sides."""
    tips = [QPointF(cx + r * math.cos(a), cy + r * math.sin(a))
            for a in (-math.pi / 2, 0, math.pi / 2, math.pi)]
    path = QPainterPath()
    path.moveTo(tips[0])
    for i in range(4):
        nxt = tips[(i + 1) % 4]
        bis = -math.pi / 2 + i * math.pi / 2 + math.pi / 4
        ctrl = QPointF(cx + r * 0.16 * math.cos(bis), cy + r * 0.16 * math.sin(bis))
        path.quadTo(ctrl, nxt)
    path.closeSubpath()
    return path


# --------------------------------------------------------------------------- #
#  Painted building blocks
# --------------------------------------------------------------------------- #
class BrutalFrame(QWidget):
    """Rounded surface with a thick outline and a hard offset shadow."""

    def __init__(self, fill=WHITE, radius=20, shadow=6, border=2,
                 shadow_color=INK, border_color=INK, parent=None):
        super().__init__(parent)
        self.fill = QColor(fill)
        self.radius = radius
        self.shadow = shadow
        self.border = border
        self.shadow_color = QColor(shadow_color)
        self.border_color = QColor(border_color)
        self.setContentsMargins(0, 0, shadow, shadow)

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHints(QPainter.RenderHint.Antialiasing)
        h = self.border / 2
        body = QRectF(h, h, self.width() - self.shadow - self.border,
                      self.height() - self.shadow - self.border)
        p.setPen(QPen(self.shadow_color, self.border))
        p.setBrush(self.shadow_color)
        p.drawRoundedRect(body.translated(self.shadow, self.shadow), self.radius, self.radius)
        p.setPen(QPen(self.border_color, self.border))
        p.setBrush(self.fill)
        p.drawRoundedRect(body, self.radius, self.radius)


class Card(BrutalFrame):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.setObjectName("Card")


class BrutalButton(QPushButton):
    """Pill button with a hard shadow. variant: primary | secondary."""

    def __init__(self, text: str, variant: str = "primary", static: bool = False, parent=None):
        super().__init__(text, parent)
        self.variant = variant
        self.static = static
        self.shadow = 5
        self.setObjectName("Primary" if variant == "primary" else "Secondary")
        self.setFont(_font(HEAD_FONT, 14, spacing=0.3))
        self.setAttribute(Qt.WidgetAttribute.WA_Hover, not static)
        if static:
            self.setFocusPolicy(Qt.FocusPolicy.NoFocus)
            self.setCursor(Qt.CursorShape.ArrowCursor)
        else:
            self.setCursor(Qt.CursorShape.PointingHandCursor)

    def sizeHint(self):
        fm = QFontMetrics(self.font())
        return QSize(fm.horizontalAdvance(self.text()) + 2 * 30 + self.shadow + 4, 46 + self.shadow)

    def minimumSizeHint(self):
        return self.sizeHint()

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHints(QPainter.RenderHint.Antialiasing | QPainter.RenderHint.TextAntialiasing)
        down = self.isDown() and not self.static
        hover = self.underMouse() and not self.static
        off = 3 if down else 0
        w, h, s = self.width(), self.height(), self.shadow
        body = QRectF(1 + off, 1 + off, w - s - 2, h - s - 2)
        r = body.height() / 2
        if self.variant == "primary":
            fill = PURPLE_DK if hover else PURPLE
            fg = WHITE
        else:
            fill = LIME if hover else CREAM
            fg = INK
        p.setPen(QPen(QColor(INK), 2))
        p.setBrush(QColor(INK))
        p.drawRoundedRect(QRectF(1 + s, 1 + s, w - s - 2, h - s - 2), r, r)
        p.setBrush(QColor(fill))
        p.drawRoundedRect(body, r, r)
        p.setPen(QColor(fg))
        p.setFont(self.font())
        p.drawText(body, Qt.AlignmentFlag.AlignCenter, self.text())
        if self.hasFocus() and not self.static:
            pen = QPen(QColor(INK), 1.4, Qt.PenStyle.DashLine)
            p.setPen(pen)
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.drawRoundedRect(body.adjusted(5, 5, -5, -5), r - 5, r - 5)


class Doodle(QWidget):
    """Hand-drawn curly arrow that sits beside page titles."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(56)
        self.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)

    def sizeHint(self):
        return QSize(150, 56)

    def minimumSizeHint(self):
        return QSize(0, 56)

    def paintEvent(self, event):
        if self.width() < 90:          # not enough room: stay out of the title's way
            return
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setPen(QPen(QColor(INK), 2.0, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap,
                      Qt.PenJoinStyle.RoundJoin))
        path = QPainterPath()
        path.moveTo(6, 34)
        path.cubicTo(30, 8, 58, 52, 74, 30)
        path.cubicTo(84, 14, 70, 14, 78, 30)
        path.cubicTo(92, 52, 116, 26, 140, 14)
        p.drawPath(path)
        p.drawLine(QPointF(140, 14), QPointF(126, 12))
        p.drawLine(QPointF(140, 14), QPointF(133, 27))


class Sparkles(QWidget):
    """Small decorative cluster used at the right of page headers."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(150, 76)

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        star = _star(104, 38, 30)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor(INK))
        p.drawPath(star.translated(5, 5))
        p.setPen(QPen(QColor(INK), 2))
        p.setBrush(QColor(PURPLE))
        p.drawPath(star)
        p.setPen(QPen(QColor("#8f93ad"), 1.6))
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawPath(_star(34, 52, 12))
        p.setPen(QPen(QColor(INK), 2))
        p.setBrush(QColor(LIME))
        p.drawEllipse(QPointF(52, 14), 7, 7)


class HeroArt(QWidget):
    """Lime illustration panel for the dashboard hero."""

    W, H = 560.0, 300.0

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumSize(380, 236)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

    @staticmethod
    def _eye(p, cx, cy, w, h, pupil):
        path = QPainterPath()
        path.moveTo(cx - w / 2, cy)
        path.quadTo(cx, cy - h * 2, cx + w / 2, cy)
        path.quadTo(cx, cy + h * 2, cx - w / 2, cy)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor(WHITE))
        p.drawPath(path)
        p.setBrush(QColor(NAVY))
        p.drawEllipse(QPointF(cx, cy), pupil, pupil)

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHints(QPainter.RenderHint.Antialiasing | QPainter.RenderHint.TextAntialiasing)
        s = min(self.width() / self.W, self.height() / self.H)
        p.translate((self.width() - self.W * s) / 2, (self.height() - self.H * s) / 2)
        p.scale(s, s)
        ink = QColor(INK)

        # lime panel
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor(LIME))
        p.drawRoundedRect(QRectF(70, 36, 440, 248), 36, 36)

        # dashed selection + cursor
        p.setPen(QPen(ink, 1.6, Qt.PenStyle.DashLine))
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawRect(QRectF(96, 56, 74, 62))
        cur = QPolygonF([QPointF(0, 0), QPointF(0, 27), QPointF(7, 21), QPointF(12, 32),
                         QPointF(17, 30), QPointF(12, 19), QPointF(21, 19)])
        cur.translate(150, 78)
        p.setPen(QPen(ink, 1.2, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
        p.setBrush(ink)
        p.drawPolygon(cur)

        # watching-eyes window
        frame = QRectF(236, 70, 262, 150)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(ink)
        p.drawRoundedRect(frame.translated(7, 7), 16, 16)
        p.setPen(QPen(ink, 2))
        p.setBrush(QColor(WHITE))
        p.drawRoundedRect(frame, 16, 16)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor(NAVY))
        p.drawRoundedRect(QRectF(246, 80, 242, 104), 11, 11)
        self._eye(p, 366, 106, 84, 17, 9)
        self._eye(p, 410, 136, 62, 13, 6.5)
        self._eye(p, 354, 160, 34, 7, 3.4)
        # player bar
        p.setBrush(ink)
        p.drawPolygon(QPolygonF([QPointF(254, 194), QPointF(254, 206), QPointF(264, 200)]))
        p.setPen(QPen(QColor("#b8bacb"), 3, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        p.drawLine(QPointF(276, 200), QPointF(440, 200))
        p.setPen(QPen(ink, 3, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        p.drawLine(QPointF(276, 200), QPointF(370, 200))
        p.setPen(ink)
        p.setFont(_font(HEAD_FONT, 10, bold=True))
        p.drawText(QRectF(440, 190, 50, 20), Qt.AlignmentFlag.AlignCenter, "LIVE")

        # shield card
        card = QRectF(84, 172, 148, 92)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(ink)
        p.drawRoundedRect(card.translated(6, 6), 10, 10)
        p.setPen(QPen(ink, 2))
        p.setBrush(QColor(WHITE))
        p.drawRoundedRect(card, 10, 10)
        shield = QPainterPath()
        sx, sy = 114, 200
        shield.moveTo(sx, sy - 16)
        shield.lineTo(sx + 14, sy - 10)
        shield.lineTo(sx + 13, sy + 4)
        shield.quadTo(sx + 10, sy + 14, sx, sy + 18)
        shield.quadTo(sx - 10, sy + 14, sx - 13, sy + 4)
        shield.lineTo(sx - 14, sy - 10)
        shield.closeSubpath()
        p.setPen(QPen(ink, 2, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
        p.setBrush(QColor(LIME))
        p.drawPath(shield)
        p.setBrush(Qt.BrushStyle.NoBrush)
        chk = QPainterPath()
        chk.moveTo(sx - 6, sy + 1)
        chk.lineTo(sx - 1, sy + 7)
        chk.lineTo(sx + 8, sy - 6)
        p.drawPath(chk)
        p.setPen(QPen(ink, 1.1))
        for i, x2 in enumerate((166, 150, 166)):
            y = 234 + i * 9
            p.drawLine(QPointF(98, y), QPointF(x2, y))
        mini = QRectF(176, 186, 40, 56)
        p.setPen(QPen(ink, 1.6))
        p.setBrush(QColor(PURPLE))
        p.drawRoundedRect(mini, 5, 5)
        p.setPen(QPen(QColor(WHITE), 1.4))
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawPath(_star(196, 208, 9))
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor(LIME))
        p.drawRoundedRect(QRectF(182, 230, 28, 6), 3, 3)

        # purple sparkle
        star = _star(496, 50, 38)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(ink)
        p.drawPath(star.translated(5, 5))
        p.setPen(QPen(ink, 2))
        p.setBrush(QColor(PURPLE))
        p.drawPath(star)

        # padlock
        p.setPen(QPen(ink, 5, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawArc(QRectF(440, 220, 20, 28), 0, 180 * 16)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(ink)
        p.drawRoundedRect(QRectF(432, 238, 36, 28), 5, 5)
        p.setBrush(QColor(LIME))
        p.drawEllipse(QPointF(450, 249), 3.6, 3.6)
        p.drawRect(QRectF(448.6, 250, 2.8, 8))

        # hash grid
        p.setPen(QPen(ink, 1.1))
        for x in (490, 518):
            p.drawLine(QPointF(x, 238), QPointF(x, 294))
        for y in (254, 278):
            p.drawLine(QPointF(476, y), QPointF(532, y))


class DarkBand(QWidget):
    """Full-bleed navy section with faint sparkle outlines."""

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.fillRect(self.rect(), QColor(NAVY))
        p.setPen(QPen(QColor("#6f7391"), 1.4))
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawPath(_star(22, 22, 11))
        p.drawPath(_star(self.width() - 26, self.height() - 24, 16))
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor("#6f7391"))
        p.drawPath(_star(40, 38, 5))


def make_header(light: str, bold: str, subtitle: str, joiner: str = " ") -> QWidget:
    """Page header: light + bold title, hand-drawn arrow, sparkle cluster."""
    wrap = QWidget()
    row = QHBoxLayout(wrap)
    row.setContentsMargins(0, 0, 0, 0)
    row.setSpacing(0)
    col = QVBoxLayout()
    col.setSpacing(2)
    trow = QHBoxLayout()
    trow.setSpacing(10)
    title = QLabel(f"{light}{joiner}<b>{bold}</b>")
    title.setObjectName("PageTitle")
    title.setTextFormat(Qt.TextFormat.RichText)
    trow.addWidget(title)
    trow.addWidget(Doodle(), 0, Qt.AlignmentFlag.AlignBottom)
    trow.addStretch()
    sub = QLabel(subtitle)
    sub.setObjectName("PageSub")
    col.addLayout(trow)
    col.addWidget(sub)
    row.addLayout(col, 1)
    row.addWidget(Sparkles(), 0, Qt.AlignmentFlag.AlignTop)
    return wrap


def card_tag(text: str) -> QLabel:
    tag = QLabel(text)
    tag.setObjectName("CardTag")
    return tag


def page_layout(page: QWidget, spacing: int = 14) -> QVBoxLayout:
    root = QVBoxLayout(page)
    root.setContentsMargins(44, 10, 44, 30)
    root.setSpacing(spacing)
    return root


class MonitorBridge(QObject):
    processes = Signal(list)
    snapshot = Signal(object)
    event = Signal(object)
    alert = Signal(object)
    error = Signal(str)

    def __init__(self, monitor):
        super().__init__()
        self.monitor = monitor
        monitor.on_processes = self._processes
        monitor.on_snapshot = self._snapshot
        monitor.on_event = self._event
        monitor.on_alert = self._alert
        monitor.on_error = self._error

    def _processes(self, value): self.processes.emit(value)
    def _snapshot(self, value): self.snapshot.emit(value)
    def _event(self, value): self.event.emit(value)
    def _alert(self, value): self.alert.emit(value)
    def _error(self, value): self.error.emit(value)


class DashboardPage(QWidget):
    def __init__(self, main):
        super().__init__()
        self.main = main
        root = QVBoxLayout(self); root.setContentsMargins(0, 0, 0, 0); root.setSpacing(0)

        # ---- hero -------------------------------------------------------
        hero = QWidget()
        hl = QHBoxLayout(hero); hl.setContentsMargins(44, 0, 44, 14); hl.setSpacing(24)
        left = QVBoxLayout(); left.setSpacing(10)
        left.addStretch(1)
        trow = QHBoxLayout(); trow.setSpacing(12)
        title = QLabel("Security <b>Overview</b>"); title.setObjectName("HeroTitle")
        title.setTextFormat(Qt.TextFormat.RichText)
        trow.addWidget(title); trow.addWidget(Doodle(), 0, Qt.AlignmentFlag.AlignBottom); trow.addStretch()
        left.addLayout(trow)
        sub = QLabel("Unified Sentinel-X protection center. Malware scanning, process behavior "
                     "monitoring, URL analysis and ransomware activity detection working together "
                     "on this device.")
        sub.setObjectName("HeroText"); sub.setWordWrap(True); sub.setMaximumWidth(470)
        left.addWidget(sub)
        left.addSpacing(8)
        brow = QHBoxLayout(); brow.setSpacing(14)
        scan_btn = BrutalButton("Scan a File", "primary"); scan_btn.clicked.connect(lambda: self.main.go(1))
        url_btn = BrutalButton("Check a URL", "secondary"); url_btn.clicked.connect(lambda: self.main.go(3))
        brow.addWidget(scan_btn); brow.addWidget(url_btn); brow.addStretch()
        left.addLayout(brow)
        left.addStretch(1)
        hl.addLayout(left, 11)
        hl.addWidget(HeroArt(), 10)
        root.addWidget(hero, 0)

        # ---- stat strip ---------------------------------------------------
        strip_wrap = QWidget()
        sw = QHBoxLayout(strip_wrap); sw.setContentsMargins(44, 0, 44, 24)
        strip = BrutalFrame(fill=CREAM, radius=22, shadow=6)
        st = QHBoxLayout(strip); st.setContentsMargins(30, 14, 26, 14); st.setSpacing(0)
        lead = QLabel("Protection<br>Snapshot"); lead.setObjectName("StripLead")
        lead.setTextFormat(Qt.TextFormat.RichText)
        st.addWidget(lead); st.addSpacing(26)

        self.cards = {}
        items = [
            ("modules", "Active Modules", "3 / 4", COLORS["accent"]),
            ("processes", "Running Processes", "0", COLORS["accent2"]),
            ("high", "High-Risk Processes", "0", COLORS["danger"]),
            ("alerts", "Security Alerts", "0", COLORS["warn"]),
        ]
        for key, label, value, accent in items:
            div = QFrame(); div.setObjectName("StripDivider"); div.setFixedWidth(1)
            st.addWidget(div); st.addSpacing(26)
            col = QVBoxLayout(); col.setSpacing(0)
            l = QLabel(label); l.setObjectName("CardTitle")
            v = QLabel(value); v.setObjectName("Big"); v.setStyleSheet(f"color:{accent};")
            col.addWidget(l); col.addWidget(v)
            st.addLayout(col, 1); self.cards[key] = v
        sw.addWidget(strip)
        root.addWidget(strip_wrap, 0)

        # ---- dark band: health + activity ---------------------------------
        band = DarkBand()
        bl = QHBoxLayout(band); bl.setContentsMargins(44, 30, 44, 30); bl.setSpacing(30)

        system = Card(shadow_color=PURPLE, radius=20, shadow=7)
        sl = QVBoxLayout(system); sl.setContentsMargins(22, 20, 22, 20); sl.setSpacing(12)
        sl.addWidget(card_tag("System Health"), 0, Qt.AlignmentFlag.AlignLeft)
        self.health = QLabel("●  Monitoring initializing"); self.health.setObjectName("Status"); sl.addWidget(self.health)
        self.rw_status = QLabel("●  Ransomware monitor paused"); self.rw_status.setObjectName("Status")
        self.rw_status.setStyleSheet(f"color:{COLORS['warn']};"); sl.addWidget(self.rw_status)
        self.cpu = QProgressBar(); self.cpu.setRange(0, 100); self.cpu.setFormat("CPU  %p%")
        self.mem = QProgressBar(); self.mem.setRange(0, 100); self.mem.setFormat("Memory  %p%")
        self.mem.setStyleSheet(f"QProgressBar::chunk {{ background: {LIME}; border-radius: 9px; margin: 2px; }}")
        sl.addWidget(self.cpu); sl.addWidget(self.mem)
        sl.addStretch(1)
        bl.addWidget(system, 1)

        activity = Card(shadow_color=LIME, radius=20, shadow=7)
        al = QVBoxLayout(activity); al.setContentsMargins(22, 20, 22, 20); al.setSpacing(12)
        al.addWidget(card_tag("Live Activity"), 0, Qt.AlignmentFlag.AlignLeft)
        self.activity = QListWidget(); al.addWidget(self.activity)
        bl.addWidget(activity, 2)
        root.addWidget(band, 1)

    _proc_alerts = 0
    _rw_alerts = 0

    def set_alert_counts(self, process=None, ransomware=None):
        """Security Alerts card = process-monitor alerts + open ransomware alerts."""
        if process is not None:
            self._proc_alerts = process
        if ransomware is not None:
            self._rw_alerts = ransomware
        self.cards["alerts"].setText(str(self._proc_alerts + self._rw_alerts))

    def set_ransomware_state(self, running, folders, open_alerts):
        if running:
            self.rw_status.setText(f"●  Ransomware monitor active • {folders} folder(s)")
            self.rw_status.setStyleSheet(f"color:{COLORS['safe']};")
        else:
            self.rw_status.setText("●  Ransomware monitor paused")
            self.rw_status.setStyleSheet(f"color:{COLORS['warn']};")
        self.set_alert_counts(ransomware=open_alerts)

    def add_ransomware_alert(self, alert):
        self.activity.insertItem(0, QListWidgetItem(
            f"[RANSOM] {alert['risk_level']} • {alert['folder']} • {alert['event_count']} events"))

    def update_snapshot(self, s):
        self.cards["processes"].setText(str(s.total_processes))
        self.cards["high"].setText(str(s.high_risk))
        self.set_alert_counts(process=s.critical_alerts)
        self.cpu.setValue(int(s.cpu_percent))
        self.mem.setValue(int(s.memory_percent))
        self.health.setText("●  REAL-TIME MONITORING ACTIVE")

    def add_event(self, event):
        item = QListWidgetItem(event.timeline_line())
        self.activity.insertItem(0, item)
        while self.activity.count() > 80:
            self.activity.takeItem(self.activity.count()-1)


class MalwarePage(QWidget):
    def __init__(self, main):
        super().__init__()
        self.main = main
        root = page_layout(self, 16)
        root.addWidget(make_header("Malware", "Scanner",
                                   "Static analysis • signatures • heuristics • Random Forest ML"))

        card = Card(); lay = QVBoxLayout(card); lay.setContentsMargins(22, 20, 22, 20); lay.setSpacing(12)
        self.file_label = QLabel("No file selected")
        self.file_label.setObjectName("FileField")
        self.file_label.setMinimumWidth(0)
        self.file_label.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        row = QHBoxLayout(); row.setSpacing(14)
        choose = BrutalButton("Choose File", "secondary"); choose.clicked.connect(self.choose)
        scan = BrutalButton("Scan File", "primary"); scan.clicked.connect(self.scan)
        row.addWidget(self.file_label,1); row.addWidget(choose); row.addWidget(scan)
        lay.addLayout(row)
        root.addWidget(card)

        vcard = BrutalFrame(radius=20, shadow=6)
        vl = QVBoxLayout(vcard); vl.setContentsMargins(14, 6, 14, 6)
        self.verdict = QLabel("READY TO SCAN"); self.verdict.setObjectName("Verdict")
        self.verdict.setAlignment(Qt.AlignmentFlag.AlignCenter)
        vl.addWidget(self.verdict)
        root.addWidget(vcard)

        details = Card(); dl = QVBoxLayout(details); dl.setContentsMargins(22, 18, 22, 20); dl.setSpacing(12)
        dl.addWidget(card_tag("Scan Details"), 0, Qt.AlignmentFlag.AlignLeft)
        self.meta = QLabel("File information will appear here.")
        self.meta.setWordWrap(True); self.meta.setTextFormat(Qt.TextFormat.RichText)
        self.meta.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        dl.addWidget(self.meta)
        self.score = QProgressBar(); self.score.setRange(0,100); self.score.setValue(0); self.score.setFormat("Risk score  %p / 100")
        dl.addWidget(self.score)
        self.reasons = QListWidget(); dl.addWidget(self.reasons,1)
        root.addWidget(details,1)
        self.path = None

    def choose(self):
        path, _ = QFileDialog.getOpenFileName(self, "Choose file to scan")
        if path:
            self.path = path
            self.file_label.setText(path)

    def scan(self):
        if not self.path:
            QMessageBox.information(self, "Choose a file", "Please choose a file first.")
            return
        try:
            self.verdict.setText("SCANNING…")
            QApplication.processEvents()
            data = Path(self.path).read_bytes()
            result = scan_file(Path(self.path).name, data)
            label = result.get("final_label", "ERROR")
            score = int(result.get("final_score", 0) or 0)
            self.score.setValue(score)
            self.verdict.setText(f"{label}   •   {score}/100")
            if label == "SAFE":
                self.verdict.setStyleSheet(f"color:{COLORS['safe']};")
            elif label == "SUSPICIOUS":
                self.verdict.setStyleSheet(f"color:{COLORS['warn']};")
            else:
                self.verdict.setStyleSheet(f"color:{COLORS['danger']};")

            ml = result.get("ml_result") or {}
            ml_text = "ML unavailable"
            if ml.get("available"):
                ml_text = f"ML: {ml.get('prediction')} ({float(ml.get('confidence',0))*100:.1f}%)"
            self.meta.setText(
                f"<b>File:</b> {result.get('filename')} &nbsp;&nbsp; "
                f"<b>Type:</b> {result.get('file_type')}<br>"
                f"<b>SHA-256:</b> {result.get('sha256')}<br>"
                f"<b>Entropy:</b> {result.get('entropy')} &nbsp;&nbsp; "
                f"<b>Signature:</b> {result.get('signature_match') or 'No match'}<br>"
                f"<b>{ml_text}</b>"
            )
            self.reasons.clear()
            reasons = result.get("reasons") or []
            if not reasons:
                reasons = ["No detection indicators were triggered."]
            for r in reasons:
                self.reasons.addItem("• " + str(r))
            self.main.last_scan = f"{label} ({score})"
            self.main.refresh_dashboard()
        except Exception as exc:
            traceback.print_exc()
            QMessageBox.critical(self, "Scan error", str(exc))
            self.verdict.setText("SCAN ERROR")


class PhishingPage(QWidget):
    """Desktop PhishGuard page using the supplied custom KNN detector."""
    def __init__(self, main):
        super().__init__()
        self.main = main
        self.dataset_urls = []
        self.dataset_labels = []
        self.training_features = []
        self.minimums = []
        self.maximums = []
        self._load_model()

        root = page_layout(self, 16)
        root.addWidget(make_header("Phish", "Guard",
                                   "URL analysis • lexical features • custom K-Nearest Neighbors", joiner=""))

        card = Card()
        lay = QVBoxLayout(card)
        lay.setContentsMargins(22, 20, 22, 20)
        lay.setSpacing(14)

        lay.addWidget(card_tag("Enter a website URL to analyze"), 0, Qt.AlignmentFlag.AlignLeft)

        row = QHBoxLayout()
        row.setSpacing(14)
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://example.com")
        self.url_input.setMinimumHeight(46)
        self.url_input.returnPressed.connect(self.analyze)
        analyze = BrutalButton("Analyze URL", "primary")
        analyze.clicked.connect(self.analyze)
        row.addWidget(self.url_input, 1)
        row.addWidget(analyze)
        lay.addLayout(row)
        root.addWidget(card)

        vcard = BrutalFrame(radius=20, shadow=6)
        vl = QVBoxLayout(vcard); vl.setContentsMargins(14, 6, 14, 6)
        self.status = QLabel("READY TO ANALYZE")
        self.status.setObjectName("Verdict")
        self.status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        vl.addWidget(self.status)
        root.addWidget(vcard)

        details = Card()
        dl = QVBoxLayout(details)
        dl.setContentsMargins(22, 18, 22, 20)
        dl.setSpacing(12)
        dl.addWidget(card_tag("URL Analysis"), 0, Qt.AlignmentFlag.AlignLeft)
        self.meta = QLabel("URL details and detected indicators will appear here.")
        self.meta.setWordWrap(True); self.meta.setTextFormat(Qt.TextFormat.RichText)
        self.meta.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        dl.addWidget(self.meta)
        self.reasons = QListWidget()
        dl.addWidget(self.reasons, 1)
        root.addWidget(details, 1)

    def _load_model(self):
        dataset = BASE_DIR / "phishguard" / "dataset.csv"
        urls, labels = [], []
        with dataset.open("r", encoding="utf-8") as f:
            next(f, None)
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.rsplit(",", 1)
                if len(parts) != 2:
                    continue
                urls.append(parts[0].strip())
                labels.append(int(parts[1].strip()))
        raw = [extract_features(url) for url in urls]
        minimums, maximums = calculate_parameters(raw)
        self.dataset_urls = urls
        self.dataset_labels = labels
        self.training_features = normalize_data(raw, minimums, maximums)
        self.minimums = minimums
        self.maximums = maximums

    def analyze(self):
        url = self.url_input.text().strip()
        if not url:
            QMessageBox.information(self, "Enter a URL", "Please enter a URL first.")
            return
        if not is_valid_url(url):
            self.status.setText("INVALID URL")
            self.status.setStyleSheet(f"color:{COLORS['warn']};")
            self.meta.setText("Use a complete URL beginning with http:// or https://.")
            self.reasons.clear()
            return
        try:
            features = extract_features(url)
            normalized = normalize_data([features], self.minimums, self.maximums)[0]
            prediction = predict(self.training_features, self.dataset_labels, normalized, k=3)

            if prediction == 1:
                self.status.setText("PHISHING URL DETECTED")
                self.status.setStyleSheet(f"color:{COLORS['danger']};")
                label = "PHISHING"
            else:
                self.status.setText("LEGITIMATE URL")
                self.status.setStyleSheet(f"color:{COLORS['safe']};")
                label = "LEGITIMATE"

            self.meta.setText(
                f"<b>URL:</b> {url}<br>"
                f"<b>Prediction:</b> {label}<br>"
                f"<b>Domain length:</b> {features[1]} &nbsp;&nbsp; "
                f"<b>HTTPS:</b> {'Yes' if features[12] else 'No'}<br>"
                f"<b>IP address:</b> {'Yes' if features[16] else 'No'} &nbsp;&nbsp; "
                f"<b>Suspicious words:</b> {features[22]} &nbsp;&nbsp; "
                f"<b>Suspicious symbols:</b> {features[23]}"
            )
            self.reasons.clear()
            indicators = []
            if features[16]: indicators.append("URL uses an IP address instead of a normal domain.")
            if features[22] > 0: indicators.append(f"Contains {features[22]} suspicious security-related word(s).")
            if features[23] > 0: indicators.append(f"Contains {features[23]} suspicious symbol(s).")
            if features[28]: indicators.append("Uses a TLD marked suspicious by the project rules.")
            if features[29]: indicators.append("Contains excessive subdomains.")
            if features[14]: indicators.append("Contains an @ symbol in the URL.")
            if features[15]: indicators.append("Contains a double slash inside the path.")
            if not indicators:
                indicators.append("No extra URL indicators were triggered by the project rules.")
            for item in indicators:
                self.reasons.addItem("• " + item)

            self.main.last_phishing = label
            self.main.refresh_dashboard()
        except Exception as exc:
            traceback.print_exc()
            QMessageBox.critical(self, "PhishGuard error", str(exc))
            self.status.setText("ANALYSIS ERROR")


class ProcessPage(QWidget):
    def __init__(self, main):
        super().__init__()
        self.main = main
        root = page_layout(self, 14)
        root.addWidget(make_header("Process", "Monitor",
                                   "Real-time process visibility and behavior risk analysis"))

        row = QHBoxLayout()
        self.status = QLabel("● Starting monitor…"); self.status.setObjectName("Pill")
        self.toggle = BrutalButton("Pause Monitoring", "secondary")
        self.toggle.clicked.connect(self.toggle_monitor)
        row.addWidget(self.status); row.addStretch(); row.addWidget(self.toggle)
        root.addLayout(row)

        tcard = Card(radius=20, shadow=6)
        tl = QVBoxLayout(tcard); tl.setContentsMargins(16, 16, 16, 16)
        self.table = QTableWidget(0,6)
        self.table.setHorizontalHeaderLabels(["PID","PROCESS","CPU","MEMORY","RISK","STATUS"])
        self.table.setAlternatingRowColors(True)
        self.table.setSortingEnabled(True)
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        self.table.horizontalHeader().setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setColumnWidth(0,70); self.table.setColumnWidth(1,230)
        tl.addWidget(self.table)
        root.addWidget(tcard,1)

    def toggle_monitor(self):
        if self.main.monitor.running:
            self.main.monitor.stop_monitoring()
            self.toggle.setText("Resume Monitoring")
            self.status.setText("● Monitoring paused")
            self.status.setStyleSheet(f"color:{COLORS['warn']};")
        else:
            self.main.monitor.start_monitoring()
            self.toggle.setText("Pause Monitoring")
            self.status.setText("● Monitoring active")
            self.status.setStyleSheet(f"color:{COLORS['safe']};")
        self.toggle.updateGeometry()
        self.toggle.update()

    def update_processes(self, processes):
        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        # Keep the UI responsive by showing the most relevant processes first.
        processes = sorted(processes, key=lambda p: p.risk_score, reverse=True)[:120]
        for p in processes:
            r = self.table.rowCount(); self.table.insertRow(r)
            vals = [str(p.pid), p.name or "Unknown", f"{p.cpu_percent:.1f}%",
                    f"{p.memory_mb:.1f} MB", str(p.risk_score), p.severity.value]
            for c,v in enumerate(vals):
                item = QTableWidgetItem(v)
                if c == 4:
                    color = COLORS["danger"] if p.risk_score >= 60 else COLORS["warn"] if p.risk_score >= 30 else COLORS["safe"]
                    item.setForeground(QColor(color))
                self.table.setItem(r,c,item)
        self.table.setSortingEnabled(True)


class IntField(QLineEdit):
    """Numeric input in the app's standard input style (value()/setValue() like a spin box)."""

    def __init__(self, low, high, value):
        super().__init__(str(value))
        self.low, self.high = low, high
        self.setValidator(QIntValidator(low, high, self))
        self.setFixedSize(110, 32)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter); self.setStyleSheet("padding: 2px 10px; border-radius: 16px;")

    def value(self):
        try:
            return min(self.high, max(self.low, int(self.text())))
        except ValueError:
            return self.low


class RansomwareBridge(QObject):
    """Moves watchdog-thread filesystem callbacks onto the GUI thread."""
    event = Signal(str, str, str)

    def emit_event(self, typ, path, folder):
        self.event.emit(str(typ), str(path), str(folder))


class RansomwarePage(QWidget):
    """Ransomware Monitor: folder behavior monitoring, alerts, quarantine, settings."""

    alert_raised = Signal(dict)
    state_changed = Signal()

    SECTIONS = ["Alerts", "Activity", "Folders", "Quarantine", "Settings"]
    SETTING_FIELDS = [
        ("window_seconds", "Detection window (seconds)"),
        ("modification_threshold", "Modification threshold"),
        ("rename_threshold", "Rename threshold"),
        ("delete_threshold", "Deletion threshold"),
        ("threshold_medium", "Medium risk score"),
        ("threshold_high", "High risk score"),
        ("threshold_critical", "Critical risk score"),
        ("log_retention_days", "Log retention (days)"),
    ]

    def __init__(self, main):
        super().__init__()
        self.main = main
        self.data_dir = rw_data_dir(BASE_DIR)
        self.db = RansomwareDB(self.data_dir / "ransomware.db")
        try:
            self.db.prune_events(self.db.settings().get("log_retention_days", "90"))
        except Exception:
            traceback.print_exc()
        self.quarantine_mgr = QuarantineManager(self.db, self.data_dir / "quarantine")
        self.engine = DetectionEngine(**self._engine_settings())
        self.bridge = RansomwareBridge()
        self.bridge.event.connect(self._handle_event)
        self.monitor = RansomwareMonitor(self.bridge.emit_event) if RansomwareMonitor else None
        self._ignored_root = os.path.normcase(str(self.data_dir.resolve()))

        root = page_layout(self, 12)
        root.addWidget(make_header("Ransomware", "Monitor",
                                   "Folder behavior monitoring • burst scoring • safe quarantine"))

        # ---- status row ---------------------------------------------------
        row = QHBoxLayout()
        self.status = QLabel("● Protection paused"); self.status.setObjectName("Pill")
        self.toggle = BrutalButton("Start Protection", "primary")
        self.toggle.clicked.connect(self.toggle_protection)
        row.addWidget(self.status); row.addStretch(); row.addWidget(self.toggle)
        root.addLayout(row)

        self.banner = QLabel(""); self.banner.setObjectName("CardTag"); self.banner.setWordWrap(True)
        self.banner.setVisible(False)
        root.addWidget(self.banner)

        # ---- stat strip ---------------------------------------------------
        strip = BrutalFrame(fill=CREAM, radius=22, shadow=6)
        st = QHBoxLayout(strip); st.setContentsMargins(26, 8, 22, 8); st.setSpacing(0)
        self.stat = {}
        for i, (key, label, accent) in enumerate([
                ("folders", "Protected Folders", COLORS["accent"]),
                ("events", "Events Processed", COLORS["accent2"]),
                ("alerts", "Open Alerts", COLORS["danger"]),
                ("quarantine", "Quarantined Files", COLORS["warn"])]):
            if i:
                div = QFrame(); div.setObjectName("StripDivider"); div.setFixedWidth(1)
                st.addWidget(div); st.addSpacing(26)
            col = QVBoxLayout(); col.setSpacing(0)
            l = QLabel(label); l.setObjectName("CardTitle")
            v = QLabel("0"); v.setObjectName("Big"); v.setStyleSheet(f"color:{accent};")
            col.addWidget(l); col.addWidget(v)
            st.addLayout(col, 1); self.stat[key] = v
        root.addWidget(strip)

        # ---- section pill nav ----------------------------------------------
        navrow = QHBoxLayout()
        pill = QFrame(); pill.setObjectName("NavPill")
        pl = QHBoxLayout(pill); pl.setContentsMargins(5, 5, 5, 5); pl.setSpacing(2)
        self.sec_btns = []
        for i, name in enumerate(self.SECTIONS):
            b = QPushButton(name); b.setObjectName("Nav"); b.setCheckable(True)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.clicked.connect(lambda checked, idx=i: self.show_section(idx))
            pl.addWidget(b); self.sec_btns.append(b)
        navrow.addWidget(pill); navrow.addStretch()
        root.addLayout(navrow)

        self.sections = QStackedWidget()
        self.sections.addWidget(self._build_alerts())
        self.sections.addWidget(self._build_activity())
        self.sections.addWidget(self._build_folders())
        self.sections.addWidget(self._build_quarantine())
        self.sections.addWidget(self._build_settings())
        root.addWidget(self.sections, 1)

        if self.monitor is None:
            self.toggle.setEnabled(False)
            self.status.setText("● watchdog not installed")
            self.status.setStyleSheet(f"color:{COLORS['danger']};")
            self.banner.setText("Install the 'watchdog' package (pip install watchdog) to enable "
                                "real-time folder monitoring.")
            self.banner.setVisible(True)

        self.show_section(0)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._tick)
        self.timer.start(2500)
        self.refresh()

    # ---------------------------------------------------------------- build
    @staticmethod
    def _make_table(headers, widths=()):
        t = QTableWidget(0, len(headers))
        t.setHorizontalHeaderLabels(headers)
        t.setAlternatingRowColors(True)
        t.verticalHeader().setVisible(False)
        t.setShowGrid(False)
        t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        t.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        t.horizontalHeader().setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        t.horizontalHeader().setStretchLastSection(True)
        for i, w in enumerate(widths):
            t.setColumnWidth(i, w)
        return t

    def _panel(self, toolbar_widgets, table, footer=None):
        """Card holding an optional toolbar row, a table and an optional footer label."""
        page = QWidget()
        lay = QVBoxLayout(page); lay.setContentsMargins(0, 0, 0, 0); lay.setSpacing(10)
        bar = QHBoxLayout(); bar.setSpacing(12)
        for w in toolbar_widgets:
            if isinstance(w, QLineEdit):
                bar.addWidget(w, 1)
            else:
                bar.addWidget(w)
        if not any(isinstance(w, QLineEdit) for w in toolbar_widgets):
            bar.addStretch()
        lay.addLayout(bar)
        card = Card(radius=20, shadow=6)
        cl = QVBoxLayout(card); cl.setContentsMargins(16, 16, 16, 16); cl.setSpacing(8)
        cl.addWidget(table, 1)
        if footer is not None:
            cl.addWidget(footer)
        lay.addWidget(card, 1)
        return page

    def _btn(self, text, fn, variant="secondary"):
        b = BrutalButton(text, variant)
        b.clicked.connect(fn)
        return b

    def _search(self, placeholder):
        e = QLineEdit(); e.setPlaceholderText(placeholder); e.setMinimumHeight(44)
        e.textChanged.connect(lambda *_: self.refresh())
        return e

    def _build_alerts(self):
        self.alert_search = self._search("Search alerts")
        self.alert_table = self._make_table(
            ["ID", "TIME", "RISK", "TYPE", "FOLDER", "EVENTS", "SCORE", "STATUS"],
            (50, 160, 120, 240, 260, 70, 70))
        self.alert_detail = QLabel("Select an alert to see its indicators and recommendation.")
        self.alert_detail.setObjectName("PageSub"); self.alert_detail.setWordWrap(True)
        self.alert_table.itemSelectionChanged.connect(self._show_alert_detail)
        return self._panel([self.alert_search,
                            self._btn("Mark Reviewed", lambda: self.set_alert_status("Reviewed")),
                            self._btn("False Positive", lambda: self.set_alert_status("False Positive")),
                            self._btn("Export", self.export_alert)],
                           self.alert_table, self.alert_detail)

    def _build_activity(self):
        self.activity_search = self._search("Search filesystem events")
        self.activity_table = self._make_table(["TIME", "TYPE", "PATH", "DESCRIPTION"], (170, 120, 420))
        return self._panel([self.activity_search,
                            self._btn("Export CSV", self.export_logs),
                            self._btn("Clear History", self.clear_logs)],
                           self.activity_table)

    def _build_folders(self):
        self.folder_table = self._make_table(["PATH", "ENABLED", "ADDED"], (520, 90))
        note = QLabel("Monitoring detects suspicious activity in these folders; it does not block "
                      "other processes from modifying files.")
        note.setObjectName("PageSub"); note.setWordWrap(True)
        return self._panel([self._btn("Add Folder", self.add_folder, "primary"),
                            self._btn("Remove", self.remove_folder),
                            self._btn("Enable / Disable", self.toggle_folder),
                            self._btn("Scan Folder", self.scan_selected)],
                           self.folder_table, note)

    def _build_quarantine(self):
        self.quarantine_table = self._make_table(["ID", "ORIGINAL PATH", "STORED PATH", "SIZE", "SHA-256"],
                                                 (50, 280, 280, 90))
        note = QLabel("Quarantine only moves a file after you confirm, and restore is hash-verified. "
                      "It cannot recover files that were already encrypted.")
        note.setObjectName("PageSub"); note.setWordWrap(True)
        return self._panel([self._btn("Quarantine File", self.quarantine_file, "primary"),
                            self._btn("Restore Selected", self.restore_item)],
                           self.quarantine_table, note)

    def _build_settings(self):
        card = Card(radius=20, shadow=6)
        lay = QVBoxLayout(card); lay.setContentsMargins(22, 18, 22, 18); lay.setSpacing(10)
        lay.addWidget(card_tag("Detection Settings"), 0, Qt.AlignmentFlag.AlignLeft)
        grid = QGridLayout(); grid.setHorizontalSpacing(14); grid.setVerticalSpacing(6)
        grid.setColumnStretch(1, 1); grid.setColumnStretch(4, 1)
        self.setting_inputs = {}
        settings = self.db.settings()
        for n, (key, label) in enumerate(self.SETTING_FIELDS):
            spin = IntField(1, 100 if "threshold" in key or "score" in label else 3650,
                            int(settings.get(key, "10")))
            r, c = n % 4, (n // 4) * 3
            grid.addWidget(QLabel(label), r, c)
            grid.addWidget(spin, r, c + 1, Qt.AlignmentFlag.AlignLeft)
            self.setting_inputs[key] = spin
        self.notify_box = QCheckBox("Show alert banner and dashboard alerts")
        self.notify_box.setChecked(settings.get("notifications_enabled", "true") == "true")
        self.autostart_box = QCheckBox("Start protection when Sentinel-X opens")
        self.autostart_box.setChecked(settings.get("start_on_launch", "false") == "true")
        grid.addWidget(self.notify_box, 4, 0, 1, 3)
        grid.addWidget(self.autostart_box, 4, 3, 1, 3)
        lay.addLayout(grid)
        lay.addWidget(self._btn("Save Settings", self.save_settings, "primary"), 0, Qt.AlignmentFlag.AlignLeft)
        lay.addStretch(1)
        page = QWidget()
        pl = QVBoxLayout(page); pl.setContentsMargins(0, 0, 0, 0); pl.addWidget(card, 1)
        return page

    def show_section(self, idx):
        self.sections.setCurrentIndex(idx)
        for i, b in enumerate(self.sec_btns):
            b.setChecked(i == idx)
        self.refresh()

    # ------------------------------------------------------------ settings
    def _engine_settings(self):
        s = self.db.settings()
        defaults = {"window_seconds": 10, "modification_threshold": 8, "rename_threshold": 6,
                    "delete_threshold": 8, "threshold_medium": 25, "threshold_high": 50,
                    "threshold_critical": 75}
        return {k: int(s.get(k, v)) for k, v in defaults.items()}

    def save_settings(self):
        vals = {k: str(v.value()) for k, v in self.setting_inputs.items()}
        n = {k: int(v) for k, v in vals.items()}
        if not (n["threshold_medium"] < n["threshold_high"] < n["threshold_critical"]):
            QMessageBox.warning(self, "Invalid settings",
                                "Risk thresholds must increase from medium to high to critical.")
            return
        for k, v in vals.items():
            self.db.set_setting(k, v)
        self.db.set_setting("notifications_enabled", str(self.notify_box.isChecked()).lower())
        self.db.set_setting("start_on_launch", str(self.autostart_box.isChecked()).lower())
        self.engine = DetectionEngine(**self._engine_settings())
        QMessageBox.information(self, "Settings saved", "Settings saved.")

    # ---------------------------------------------------------- protection
    @property
    def running(self):
        return bool(self.monitor and self.monitor.running)

    def autostart(self):
        s = self.db.settings()
        if s.get("start_on_launch", "false") == "true" and s.get("monitoring_enabled", "true") == "true":
            self.start_protection(prompt=False)

    def toggle_protection(self):
        if self.running:
            self.pause_protection()
        else:
            self.start_protection()

    def start_protection(self, prompt=True):
        if self.monitor is None:
            return
        try:
            folders = [f for f in self.db.folders(enabled_only=True) if Path(f["path"]).is_dir()]
            if not folders:
                if not prompt:
                    return
                folder = QFileDialog.getExistingDirectory(self, "Choose a folder to protect")
                if not folder:
                    return
                folder = self.db.add_folder(folder)
                self.db.set_folder_enabled(folder, True)
                folders = self.db.folders(enabled_only=True)
            paths = self.monitor.start(folders)
            self.db.log("monitor_start", "Monitoring started: " + ", ".join(paths))
        except Exception as exc:
            traceback.print_exc()
            QMessageBox.warning(self, "Cannot start protection", str(exc))
        self.refresh()
        self.state_changed.emit()

    def pause_protection(self):
        if self.monitor:
            self.monitor.stop()
        self.db.log("monitor_stop", "Monitoring paused by user")
        self.refresh()
        self.state_changed.emit()

    def stop(self):
        if self.monitor:
            self.monitor.stop()
        self.timer.stop()

    def _restart_if_running(self):
        if self.running:
            self.start_protection(prompt=False)
            if not self.running:        # last folder was removed / disabled
                self.state_changed.emit()

    def _handle_event(self, typ, path, folder):
        try:
            if os.path.normcase(os.path.abspath(path)).startswith(self._ignored_root):
                return                    # never react to our own database / quarantine writes
            self.db.log(typ, f"Filesystem {typ}", path)
            alert = self.engine.process(typ, path, folder=folder)
            if alert:
                alert["id"] = self.db.add_alert(alert)
                if self.db.settings().get("notifications_enabled", "true") == "true":
                    self.banner.setText(f"{alert['risk_level']}: {alert['description']}")
                    self.banner.setVisible(True)
                    self.alert_raised.emit(alert)
                self.state_changed.emit()
        except Exception:
            traceback.print_exc()

    # ------------------------------------------------------------- folders
    def _selected(self, table, col=0):
        r = table.currentRow()
        if r < 0:
            QMessageBox.information(self, "Select a row", "Please select a row first.")
            return None
        return table.item(r, col).text()

    def add_folder(self):
        p = QFileDialog.getExistingDirectory(self, "Choose folder to monitor")
        if p:
            self.db.add_folder(p)
            self._restart_if_running()
            self.refresh()

    def remove_folder(self):
        p = self._selected(self.folder_table)
        if p:
            self.db.remove_folder(p)
            self._restart_if_running()
            self.refresh()

    def toggle_folder(self):
        r = self.folder_table.currentRow()
        if r < 0:
            QMessageBox.information(self, "Select a row", "Please select a folder first.")
            return
        p = self.folder_table.item(r, 0).text()
        enabled = self.folder_table.item(r, 1).text() != "Yes"
        self.db.set_folder_enabled(p, enabled)
        self._restart_if_running()
        self.refresh()

    def scan_selected(self):
        r = self.folder_table.currentRow()
        folder = self.folder_table.item(r, 0).text() if r >= 0 else \
            QFileDialog.getExistingDirectory(self, "Choose folder to scan")
        if not folder:
            return
        try:
            QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
            try:
                results = scan_folder(folder)
            finally:
                QApplication.restoreOverrideCursor()
            out = self.data_dir / "scan_results.csv"
            with out.open("w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=["name", "path", "extension", "size", "modified", "sha256"])
                w.writeheader(); w.writerows(results)
            QMessageBox.information(self, "Scan complete",
                                    f"Scanned {len(results)} files. Metadata/hash results saved to:\n{out}\n\n"
                                    "This scan cannot prove whether a file is malware.")
        except Exception as exc:
            QMessageBox.warning(self, "Scan failed", str(exc))

    # -------------------------------------------------------------- alerts
    def set_alert_status(self, status):
        ident = self._selected(self.alert_table)
        if ident:
            self.db.update_alert_status(ident, status)
            self.refresh()
            self.state_changed.emit()

    def _show_alert_detail(self):
        r = self.alert_table.currentRow()
        if r < 0:
            return
        ident = self.alert_table.item(r, 0).text()
        a = next((x for x in self.db.alerts() if str(x["id"]) == ident), None)
        if a:
            self.alert_detail.setText(f"Indicators: {a['indicators']}\n{a['recommendation']}")

    def export_alert(self):
        ident = self._selected(self.alert_table)
        if not ident:
            return
        a = next((x for x in self.db.alerts() if str(x["id"]) == ident), None)
        if not a:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export alert", "sentinelx_alert.json", "JSON (*.json)")
        if path:
            Path(path).write_text(json.dumps(a, indent=2), encoding="utf-8")

    # ---------------------------------------------------------- quarantine
    def quarantine_file(self):
        p, _ = QFileDialog.getOpenFileName(self, "Select a file to quarantine")
        if not p:
            return
        if QMessageBox.question(self, "Confirm quarantine",
                                f"Move this file to quarantine?\n{p}") != QMessageBox.StandardButton.Yes:
            return
        try:
            dest = self.quarantine_mgr.quarantine(p, confirmed=True)
            QMessageBox.information(self, "Quarantined", f"File moved to {dest}")
            self.refresh()
        except Exception as exc:
            QMessageBox.warning(self, "Quarantine failed", str(exc))

    def restore_item(self):
        r = self.quarantine_table.currentRow()
        if r < 0:
            QMessageBox.information(self, "Select a row", "Please select a quarantined item first.")
            return
        ident = self.quarantine_table.item(r, 0).text()
        dest, _ = QFileDialog.getSaveFileName(self, "Restore file to", self.quarantine_table.item(r, 1).text())
        if not dest:
            return
        try:
            self.quarantine_mgr.restore(ident, dest)
            self.refresh()
            QMessageBox.information(self, "Restored", "File hash verified and file restored.")
        except Exception as exc:
            QMessageBox.warning(self, "Restore failed", str(exc))

    # ---------------------------------------------------------------- logs
    def export_logs(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export logs", "sentinelx_logs.csv", "CSV (*.csv)")
        if not path:
            return
        rows = self.db.events(self.activity_search.text())
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["id", "timestamp", "event_type", "path", "description"])
            w.writeheader(); w.writerows(rows)

    def clear_logs(self):
        if QMessageBox.question(self, "Clear history",
                                "Delete historical event logs? Alerts will be retained.") \
                != QMessageBox.StandardButton.Yes:
            return
        self.db.clear_events()
        self.db.log("history_cleared", "User cleared historical event logs")
        self.refresh()

    # ------------------------------------------------------------- refresh
    def _tick(self):
        if self.isVisible():
            self.refresh()

    @staticmethod
    def _ts(value):
        return str(value).replace("T", " ")[:19]

    def _fill(self, table, rows):
        table.setUpdatesEnabled(False)
        sel = table.currentRow()
        table.setRowCount(len(rows))
        for i, row in enumerate(rows):
            for j, v in enumerate(row):
                table.setItem(i, j, QTableWidgetItem(str(v if v is not None else "")))
        if 0 <= sel < len(rows):
            table.selectRow(sel)
        table.setUpdatesEnabled(True)

    def refresh(self):
        running = self.running
        if self.monitor is not None:
            if running:
                self.status.setText("● Protected • monitoring active")
                self.status.setStyleSheet(f"color:{COLORS['safe']};")
                self.toggle.setText("Pause Protection")
                self.toggle.variant = "secondary"
            else:
                self.status.setText("● Protection paused")
                self.status.setStyleSheet(f"color:{COLORS['warn']};")
                self.toggle.setText("Start Protection")
                self.toggle.variant = "primary"
            self.toggle.updateGeometry(); self.toggle.update()
        c = self.db.counts()
        if self.monitor is not None and c["alerts"] == 0:
            self.banner.setVisible(False)     # nothing open any more
        for key in ("folders", "events", "alerts", "quarantine"):
            self.stat[key].setText(str(c[key]))
        idx = self.sections.currentIndex()
        if idx == 0:
            rows = self.db.alerts(self.alert_search.text(), limit=300)
            self._fill(self.alert_table, [[x["id"], self._ts(x["timestamp"]), x["risk_level"], x["detection_type"],
                                           x["folder"], x["event_count"], x["risk_score"], x["status"]]
                                          for x in rows])
        elif idx == 1:
            rows = self.db.events(self.activity_search.text(), limit=500)
            self._fill(self.activity_table, [[self._ts(x["timestamp"]), x["event_type"], x["path"], x["description"]]
                                             for x in rows])
        elif idx == 2:
            rows = self.db.folders()
            self._fill(self.folder_table, [[x["path"], "Yes" if x["enabled"] else "No", x["added_at"]]
                                           for x in rows])
        elif idx == 3:
            rows = self.db.quarantine_items()
            self._fill(self.quarantine_table, [[x["id"], x["original_path"], x["quarantine_path"],
                                                x["size"], x["sha256"]] for x in rows])


class ComingSoonPage(QWidget):
    def __init__(self, title, subtitle):
        super().__init__()
        root = page_layout(self, 16)
        light, _, bold = title.partition(" ")
        root.addWidget(make_header(light, bold, subtitle))
        c = Card(); l = QVBoxLayout(c); l.setContentsMargins(28, 26, 28, 28); l.setSpacing(14)
        big = QLabel("Module ready for integration"); big.setObjectName("CardTag")
        big.setStyleSheet(f"font-size:17px; padding:8px 18px;")
        note = QLabel("This slot is intentionally prepared. When the remaining module is added, it can be connected here without redesigning the desktop application.")
        note.setWordWrap(True); note.setObjectName("PageSub")
        l.addWidget(big, 0, Qt.AlignmentFlag.AlignLeft); l.addWidget(note); l.addStretch()
        root.addWidget(c,1)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Sentinel-X • Multi-Layer Cyber Security")
        self.resize(1320, 800)
        self.setMinimumSize(1050, 680)
        self.setStyleSheet(STYLE)
        self.last_scan = "Not scanned"
        self.last_phishing = "Not analyzed"

        # Process engine uses the real uploaded monitoring core.
        self.settings = MonitorSettings()
        self.db = Database(str(BASE_DIR/"sentinelx.db"))
        self.logger = SecurityLogger(self.db)
        self.manager = ProcessManager(compute_hashes=True)
        reputation = str(BASE_DIR/"reputation.json")
        self.analyzer = SecurityAnalyzer(self.settings, reputation_path=reputation)
        self.monitor = ProcessMonitor(self.manager, self.analyzer, self.logger, self.settings)
        self.bridge = MonitorBridge(self.monitor)

        central = QWidget(); self.setCentralWidget(central)
        outer = QVBoxLayout(central); outer.setContentsMargins(0,0,0,0); outer.setSpacing(0)

        # ---- top bar: brand | pill navigation | version chip ----------------
        bar = QWidget()
        bl = QHBoxLayout(bar); bl.setContentsMargins(44, 22, 44, 14); bl.setSpacing(16)

        brand_col = QVBoxLayout(); brand_col.setSpacing(0)
        brand = QLabel(f"Sentinel<span style='color:{PURPLE}'>-X</span>"); brand.setObjectName("Brand")
        brand.setTextFormat(Qt.TextFormat.RichText)
        tag = QLabel("Multi-layer security"); tag.setObjectName("Tag")
        brand_col.addWidget(brand); brand_col.addWidget(tag)
        bl.addLayout(brand_col)
        bl.addStretch(1)

        self.stack = QStackedWidget()
        self.dashboard = DashboardPage(self)
        self.malware = MalwarePage(self)
        self.process = ProcessPage(self)
        self.phishing = PhishingPage(self)
        self.ransomware = RansomwarePage(self)
        pages = [self.dashboard,self.malware,self.process,self.phishing,self.ransomware]
        names = ["Dashboard","Malware","Processes","Phishing","Ransomware"]
        for p in pages: self.stack.addWidget(p)

        pill = QFrame(); pill.setObjectName("NavPill")
        pl = QHBoxLayout(pill); pl.setContentsMargins(5, 5, 5, 5); pl.setSpacing(2)
        self.nav = []
        for i,name in enumerate(names):
            b=QPushButton(name); b.setObjectName("Nav"); b.setCheckable(True)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.clicked.connect(lambda checked, idx=i: self.go(idx))
            pl.addWidget(b); self.nav.append(b)
        bl.addWidget(pill)
        bl.addStretch(1)
        bl.addWidget(BrutalButton("v1.0 • Local Desktop", "secondary", static=True))

        outer.addWidget(bar)
        outer.addWidget(self.stack,1)
        self.go(0)

        self.bridge.processes.connect(self._processes)
        self.bridge.snapshot.connect(self._snapshot)
        self.bridge.event.connect(self._event)
        self.bridge.alert.connect(self._alert)
        self.bridge.error.connect(self._error)

        self.ransomware.alert_raised.connect(self.dashboard.add_ransomware_alert)
        self.ransomware.state_changed.connect(self._ransomware_state)

        self.monitor.start_monitoring()
        self.ransomware.autostart()
        self._ransomware_state()

    def _ransomware_state(self):
        c = self.ransomware.db.counts()
        running = self.ransomware.running
        self.dashboard.set_ransomware_state(running, c["folders"], c["alerts"])
        self.dashboard.cards["modules"].setText(f"{3 + (1 if running else 0)} / 4")

    def go(self, idx):
        self.stack.setCurrentIndex(idx)
        for i,b in enumerate(self.nav): b.setChecked(i==idx)

    def _processes(self, processes):
        self.process.update_processes(processes)

    def _snapshot(self, snap):
        self.dashboard.update_snapshot(snap)

    def _event(self, event):
        self.dashboard.add_event(event)

    def _alert(self, alert):
        self.dashboard.set_alert_counts(process=max(1, self.dashboard._proc_alerts))

    def _error(self, msg):
        self.dashboard.health.setText("● Monitor error: " + msg[:70])
        self.dashboard.health.setStyleSheet(f"color:{COLORS['danger']};")

    def refresh_dashboard(self):
        self.dashboard.activity.insertItem(0, QListWidgetItem(f"[SCAN] Malware scan: {self.last_scan}"))
        if self.last_phishing != "Not analyzed":
            self.dashboard.activity.insertItem(0, QListWidgetItem(f"[PHISH] URL analysis: {self.last_phishing}"))

    def closeEvent(self, event):
        try:
            self.monitor.stop_monitoring()
            self.ransomware.stop()
            self.db.close()
        finally:
            event.accept()


def _load_fonts() -> None:
    """Register the bundled Lexend + Titillium Web files (falls back to Segoe UI)."""
    font_dir = BASE_DIR / "assets" / "fonts"
    if font_dir.is_dir():
        for f in sorted(font_dir.glob("*.ttf")):
            QFontDatabase.addApplicationFont(str(f))


def main():
    # Crisp rendering on any display scale (125 %, 150 %, 4K, retina...).
    QGuiApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )
    app = QApplication(sys.argv)
    app.setApplicationName("Sentinel-X")
    app.setOrganizationName("Sentinel-X")
    app.setStyle("Fusion")
    _load_fonts()
    font = QFont(BODY_FONT)
    font.setPixelSize(14)
    font.setStyleStrategy(QFont.StyleStrategy.PreferAntialias)
    font.setHintingPreference(QFont.HintingPreference.PreferNoHinting)
    app.setFont(font)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
