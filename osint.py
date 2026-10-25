# -*- coding: utf-8 -*-
"""
GHOST//OSINT — терминал разведки по открытым источникам (OSINT)
Модули: телефон, Telegram, username, IP/домен, email.
Используются ТОЛЬКО публичные данные. Применяйте законно и этично.
"""
import tkinter as tk
from tkinter import filedialog, messagebox
import threading, queue, re, socket, hashlib, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import requests

try:
    import phonenumbers
    from phonenumbers import carrier, geocoder, timezone
    HAS_PN = True
except ImportError:
    HAS_PN = False

try:
    import whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36",
      "Accept-Language": "en-US,en;q=0.9"}

# поисковые системы для построения ссылок-запросов
ENGINES = [
    ("Google", "https://www.google.com/search?q={}"),
    ("Yandex", "https://yandex.com/search/?text={}"),
    ("Bing", "https://www.bing.com/search?q={}"),
    ("DuckDuckGo", "https://duckduckgo.com/?q={}"),
    ("Startpage", "https://www.startpage.com/sp/search?query={}"),
    ("Brave", "https://search.brave.com/search?q={}"),
    ("Yahoo", "https://search.yahoo.com/search?p={}"),
    ("Mail.ru", "https://go.mail.ru/search?q={}"),
]

# сервисы проверки утечек (открываются вручную - у большинства защита от ботов/нужен ключ)
LEAK_SITES = [
    ("Have I Been Pwned", "https://haveibeenpwned.com/account/{}"),
    ("DeHashed", "https://dehashed.com/search?query={}"),
    ("LeakCheck", "https://leakcheck.io/search?query={}"),
    ("IntelligenceX", "https://intelx.io/?s={}"),
    ("ProxyNova (leaks)", "https://www.proxynova.com/tools/comb/?query={}"),
    ("Snusbase", "https://snusbase.com/search?term={}"),
]

# соцсети для прямого поиска по номеру телефона (дорки site:)
PHONE_SOCIAL_NETS = ["vk.com", "ok.ru", "t.me", "instagram.com",
                      "facebook.com", "tiktok.com", "x.com", "whatsapp.com"]

PLACEHOLDERS = {
    "AUTO":   'например: 7 904 979 87 54  /  @username  /  ivan@mail.ru  /  example.com',
    "PHONE":  'например: 7 904 979 87 54',
    "TG":     'например: @durov',
    "USER":   'например: ivan_petrov',
    "DOMAIN": 'например: example.com',
    "IP":     'например: 8.8.8.8',
    "MAIL":   'например: ivan@mail.ru',
    "PHOTO":  'ссылка на фото, например: https://site.com/photo.jpg',
}

# ---------- цвета ----------
BG, PANEL = "#000000", "#050a05"
GREEN, DGREEN, CYAN = "#00ff41", "#007a1f", "#00e5ff"
RED, YELLOW, WHITE = "#ff3131", "#ffd400", "#d0ffd8"
FONT = ("Consolas", 10)

BANNER = r"""
  ____ _   _  ___  ____ _____   __  __   ___  ____ ___ _   _ _____
 / ___| | | |/ _ \/ ___|_   _| / / / /  / _ \/ ___|_ _| \ | |_   _|
| |  _| |_| | | | \___ \ | |  / / / /  | | | \___ \| ||  \| | | |
| |_| |  _  | |_| |___) || | / /_/ /   | |_| |___) | || |\  | | |
 \____|_| |_|\___/|____/ |_|/_/(_)_/     \___/|____/___|_| \_| |_|
"""

# Формат: Название|URL|тип|маркер
# тип: s = найден при HTTP 200; n = 200 и маркер ОТСУТСТВУЕТ в тексте;
#      u = сайт блокирует ботов -> только ссылка для ручной проверки
SITES_RAW = """
GitHub|https://github.com/{}
GitLab|https://gitlab.com/{}
Bitbucket|https://bitbucket.org/{}/
Codeberg|https://codeberg.org/{}
SourceHut|https://sr.ht/~{}/
SourceForge|https://sourceforge.net/u/{}
HuggingFace|https://huggingface.co/{}
Kaggle|https://www.kaggle.com/{}
Replit|https://replit.com/@{}
CodePen|https://codepen.io/{}
Codewars|https://www.codewars.com/users/{}
Codecademy|https://www.codecademy.com/profiles/{}
HackerRank|https://www.hackerrank.com/{}
HackerOne|https://hackerone.com/{}
TryHackMe|https://tryhackme.com/p/{}
LeetCode|https://leetcode.com/{}/
Codeforces|https://codeforces.com/profile/{}
Dev.to|https://dev.to/{}
Hashnode|https://hashnode.com/@{}
Medium|https://medium.com/@{}
npm|https://www.npmjs.com/~{}
PyPI|https://pypi.org/user/{}/
RubyGems|https://rubygems.org/profiles/{}
Packagist|https://packagist.org/users/{}/
NuGet|https://www.nuget.org/profiles/{}
DockerHub|https://hub.docker.com/u/{}
Launchpad|https://launchpad.net/~{}
Keybase|https://keybase.io/{}
Gravatar|https://gravatar.com/{}
HackerNews|https://news.ycombinator.com/user?id={}|n|No such user
Hackaday|https://hackaday.io/{}
Observable|https://observablehq.com/@{}
Wikipedia EN|https://en.wikipedia.org/wiki/User:{}
Wikipedia RU|https://ru.wikipedia.org/wiki/Участник:{}
OpenStreetMap|https://www.openstreetmap.org/user/{}
Reddit|https://www.reddit.com/user/{}
Pikabu|https://pikabu.ru/@{}
Habr|https://habr.com/ru/users/{}/
Habr Career|https://career.habr.com/{}
VK|https://vk.com/{}
OK.ru|https://ok.ru/{}
LiveJournal|https://{}.livejournal.com
Drive2|https://www.drive2.ru/users/{}
Kwork|https://kwork.ru/user/{}
FL.ru|https://www.fl.ru/users/{}/
LiveLib|https://www.livelib.ru/reader/{}
Stihi.ru|https://stihi.ru/avtor/{}
Boosty|https://boosty.to/{}
Dzen|https://dzen.ru/{}
Telegram|https://t.me/{}|n|og:title" content="Telegram: Contact @{}"
Snapchat|https://www.snapchat.com/add/{}
Pinterest|https://www.pinterest.com/{}/
Tumblr|https://{}.tumblr.com
Flickr|https://www.flickr.com/people/{}
500px|https://500px.com/p/{}
DeviantArt|https://www.deviantart.com/{}
Behance|https://www.behance.net/{}
Dribbble|https://dribbble.com/{}
Unsplash|https://unsplash.com/@{}
Pixabay|https://pixabay.com/users/{}
Sketchfab|https://sketchfab.com/{}
Giphy|https://giphy.com/{}
Imgur|https://imgur.com/user/{}
Newgrounds|https://{}.newgrounds.com
Itch.io|https://{}.itch.io
Weebly|https://{}.weebly.com
WordPress|https://{}.wordpress.com
Blogger|https://{}.blogspot.com
Disqus|https://disqus.com/by/{}
Quora|https://www.quora.com/profile/{}
Flipboard|https://flipboard.com/@{}
Scribd|https://www.scribd.com/{}
SlideShare|https://www.slideshare.net/{}
Wattpad|https://www.wattpad.com/user/{}
Goodreads|https://www.goodreads.com/{}
Letterboxd|https://letterboxd.com/{}
Trakt|https://trakt.tv/users/{}
MyAnimeList|https://myanimelist.net/profile/{}
Fandom|https://www.fandom.com/u/{}
Mastodon.social|https://mastodon.social/@{}
YouTube|https://www.youtube.com/@{}
Vimeo|https://vimeo.com/{}
Dailymotion|https://www.dailymotion.com/{}
Twitch|https://www.twitch.tv/{}|u
Kick|https://kick.com/{}
YouNow|https://www.younow.com/{}
SoundCloud|https://soundcloud.com/{}
Bandcamp|https://bandcamp.com/{}
Mixcloud|https://www.mixcloud.com/{}/
Last.fm|https://www.last.fm/user/{}
Discogs|https://www.discogs.com/user/{}
Genius|https://genius.com/{}
ReverbNation|https://www.reverbnation.com/{}
Smule|https://www.smule.com/{}
RateYourMusic|https://rateyourmusic.com/~{}
Spotify|https://open.spotify.com/user/{}|u
Steam|https://steamcommunity.com/id/{}|n|The specified profile could not be found
Roblox|https://www.roblox.com/user.aspx?username={}
Minecraft|https://api.mojang.com/users/profiles/minecraft/{}
Chess.com|https://www.chess.com/member/{}
Lichess|https://lichess.org/@/{}
Speedrun.com|https://www.speedrun.com/users/{}
osu!|https://osu.ppy.sh/users/{}
Duolingo|https://www.duolingo.com/profile/{}
PCPartPicker|https://pcpartpicker.com/user/{}
Patreon|https://www.patreon.com/{}
Ko-fi|https://ko-fi.com/{}
BuyMeACoffee|https://buymeacoffee.com/{}
Gumroad|https://{}.gumroad.com
Etsy|https://www.etsy.com/shop/{}
Freelancer|https://www.freelancer.com/u/{}
ProductHunt|https://www.producthunt.com/@{}
TradingView|https://www.tradingview.com/u/{}/
Trello|https://trello.com/{}
Linktree|https://linktr.ee/{}
AllMyLinks|https://allmylinks.com/{}
About.me|https://about.me/{}
Pastebin|https://pastebin.com/u/{}
Archive.org|https://archive.org/details/@{}
Tellonym|https://tellonym.me/{}
TikTok|https://www.tiktok.com/@{}|u
Instagram|https://www.instagram.com/{}/|u
X / Twitter|https://x.com/{}|u
Facebook|https://www.facebook.com/{}|u
Threads|https://www.threads.net/@{}|u
LinkedIn|https://www.linkedin.com/in/{}|u
Tinder|https://tinder.com/@{}|u
"""
SITES = []
for _l in SITES_RAW.strip().splitlines():
    _p = _l.split("|")
    SITES.append((_p[0], _p[1], _p[2] if len(_p) > 2 else "s", _p[3] if len(_p) > 3 else ""))


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("GHOST//OSINT v1.2")
        self.geometry("1040x700")
        self.minsize(860, 560)
        self.configure(bg=BG)
        self.q = queue.Queue()
        self.mode = tk.StringVar(value="AUTO")
        self.busy = False
        self._build()
        self.after(30, self._poll)
        threading.Thread(target=self._boot, daemon=True).start()

    # ---------- UI ----------
    def _build(self):
        top = tk.Frame(self, bg=BG)
        top.pack(fill="x")
        tk.Label(top, text=BANNER, bg=BG, fg=GREEN, font=("Consolas", 8),
                 justify="left").pack(side="left", padx=8)
        info = tk.Frame(top, bg=BG)
        info.pack(side="right", padx=14)
        self.clock = tk.Label(info, bg=BG, fg=DGREEN, font=FONT)
        self.clock.pack(anchor="e")
        tk.Label(info, text="STATUS: ONLINE  |  TOR: OFF  |  OPEN SOURCES ONLY",
                 bg=BG, fg=DGREEN, font=("Consolas", 8)).pack(anchor="e")
        self._tick()

        body = tk.Frame(self, bg=BG)
        body.pack(fill="both", expand=True, padx=8, pady=4)

        side = tk.Frame(body, bg=PANEL, highlightbackground=DGREEN, highlightthickness=1)
        side.pack(side="left", fill="y", padx=(0, 6))
        tk.Label(side, text="[ МОДУЛИ ]", bg=PANEL, fg=CYAN, font=("Consolas", 10, "bold")
                 ).pack(pady=(8, 4), padx=10)
        for key, label in [("AUTO", "AUTO-DETECT"), ("PHONE", "ТЕЛЕФОН"),
                           ("TG", "TELEGRAM @"), ("USER", "USERNAME / IG / TT"),
                           ("DOMAIN", "ДОМЕН / WHOIS"), ("IP", "IP-АДРЕС"),
                           ("MAIL", "EMAIL"), ("PHOTO", "ФОТО (обратный поиск)")]:
            tk.Radiobutton(side, text=label, value=key, variable=self.mode,
                           indicatoron=False, width=17, bg=PANEL, fg=GREEN,
                           selectcolor="#003b10", activebackground="#003b10",
                           activeforeground=GREEN, font=FONT, relief="flat", bd=0,
                           pady=6, anchor="w", padx=8, cursor="hand2",
                           command=self._on_mode_change
                           ).pack(pady=2, padx=8, fill="x")
        tk.Frame(side, bg=DGREEN, height=1).pack(fill="x", padx=8, pady=8)
        self._btn(side, "СОХРАНИТЬ ОТЧЁТ", self.save).pack(padx=8, pady=2, fill="x")
        self._btn(side, "ОЧИСТИТЬ", self.clear).pack(padx=8, pady=2, fill="x")

        wrap = tk.Frame(body, bg=BG, highlightbackground=DGREEN, highlightthickness=1)
        wrap.pack(side="left", fill="both", expand=True)
        self.out = tk.Text(wrap, bg=BG, fg=GREEN, insertbackground=GREEN, font=FONT,
                           wrap="word", bd=0, padx=10, pady=8, state="disabled",
                           selectbackground="#003b10")
        sb = tk.Scrollbar(wrap, command=self.out.yview, bg=BG, troughcolor=BG)
        self.out.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.out.pack(side="left", fill="both", expand=True)
        for tag, col in [("g", GREEN), ("d", DGREEN), ("c", CYAN), ("r", RED),
                         ("y", YELLOW), ("w", WHITE)]:
            self.out.tag_config(tag, foreground=col)
        self.out.tag_config("h", foreground=CYAN, font=("Consolas", 10, "bold"))

        bar = tk.Frame(self, bg=BG)
        bar.pack(fill="x", padx=8, pady=(2, 6))
        tk.Label(bar, text="root@ghost:~#", bg=BG, fg=GREEN,
                 font=("Consolas", 11, "bold")).pack(side="left")
        self.entry = tk.Entry(bar, bg="#020802", fg=GREEN, insertbackground=GREEN,
                              font=("Consolas", 12), bd=0, highlightthickness=1,
                              highlightbackground=DGREEN, highlightcolor=GREEN)
        self.entry.pack(side="left", fill="x", expand=True, padx=8, ipady=5)
        self.entry.bind("<Return>", lambda e: self.run())
        self.entry.bind("<FocusIn>", self._clear_placeholder)
        self.entry.bind("<FocusOut>", self._restore_placeholder)
        self._ph_active = False
        self._set_placeholder()
        self.go = self._btn(bar, "▶ SCAN", self.run)
        self.go.pack(side="left")
        self.bind_all("<Key>", self._global_key)

    def _btn(self, parent, text, cmd):
        b = tk.Button(parent, text=text, command=cmd, bg="#002a0a", fg=GREEN,
                      activebackground=GREEN, activeforeground=BG, font=FONT,
                      relief="flat", bd=0, padx=12, pady=5, cursor="hand2")
        b.bind("<Enter>", lambda e: b.configure(bg="#004d14"))
        b.bind("<Leave>", lambda e: b.configure(bg="#002a0a"))
        return b

    # ---------- плейсхолдер в поле ввода ----------
    def _set_placeholder(self):
        text = PLACEHOLDERS.get(self.mode.get(), PLACEHOLDERS["AUTO"])
        self.entry.delete(0, "end")
        self.entry.insert(0, text)
        self.entry.config(fg=DGREEN)
        self._ph_active = True

    def _clear_placeholder(self, event=None):
        if getattr(self, "_ph_active", False):
            self.entry.delete(0, "end")
            self.entry.config(fg=GREEN)
            self._ph_active = False

    def _restore_placeholder(self, event=None):
        if not self.entry.get().strip():
            self._set_placeholder()

    def _on_mode_change(self):
        if getattr(self, "_ph_active", False) or not self.entry.get().strip():
            self._set_placeholder()

    def _global_key(self, event):
        # если фокус не в поле ввода и это "печатный" символ - перекидываем фокус
        # в строку ввода, чтобы можно было печатать сразу, не кликая мышью
        if self.focus_get() is self.entry:
            return
        if event.keysym in ("Tab", "Return", "Escape", "Up", "Down", "Left", "Right"):
            return
        self.entry.focus_set()

    def _tick(self):
        self.clock.config(text=datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))
        self.after(1000, self._tick)

    # ---------- вывод ----------
    def log(self, text, tag="g", delay=0.0):
        self.q.put((text, tag, delay))

    def _poll(self):
        try:
            while True:
                text, tag, _ = self.q.get_nowait()
                self.out.config(state="normal")
                self.out.insert("end", text + "\n", tag)
                self.out.see("end")
                self.out.config(state="disabled")
        except queue.Empty:
            pass
        self.after(30, self._poll)

    def clear(self):
        self.out.config(state="normal")
        self.out.delete("1.0", "end")
        self.out.config(state="disabled")

    def save(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".txt", initialfile=f"osint_{datetime.now():%Y%m%d_%H%M%S}.txt",
            filetypes=[("Text", "*.txt")])
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.out.get("1.0", "end"))
            self.log(f"[+] Отчёт сохранён: {path}", "c")

    def _boot(self):
        lines = ["[*] Инициализация ядра GHOST//OSINT ...",
                 "[*] Загрузка модулей: phone, telegram, username, domain, ip, email, photo ... OK",
                 "[*] Проверка сети ... OK",
                 f"[*] libphonenumber: {'OK' if HAS_PN else 'НЕ УСТАНОВЛЕН (pip install phonenumbers)'}",
                 f"[*] python-whois:   {'OK' if HAS_WHOIS else 'НЕ УСТАНОВЛЕН (pip install python-whois)'}",
                 f"[*] dnspython:      {'OK' if HAS_DNS else 'НЕ УСТАНОВЛЕН (pip install dnspython)'}",
                 "[+] Система готова. Введите цель и нажмите ENTER.",
                 "[!] Используйте только законно: открытые данные, без доступа к приватному.", ""]
        for l in lines:
            self.log(l, "y" if l.startswith("[!]") else "g")
            time.sleep(0.25)

    # ---------- запуск ----------
    def run(self):
        if self.busy:
            return
        target = self.entry.get().strip()
        if not target or getattr(self, "_ph_active", False):
            self.log("[!] Введите цель в строку ниже (не подсказку) и нажмите ENTER или SCAN.", "y")
            self.entry.focus_set()
            return
        mode = self.mode.get()
        if mode == "AUTO":
            mode = self.detect(target)
        self.busy = True
        self.go.config(state="disabled", text="… SCAN")
        self.log(f"\n┌──[ root@ghost ]─[ {mode} ]─[ {datetime.now():%H:%M:%S} ]", "d")
        self.log(f"└─$ target = {target}", "w")
        threading.Thread(target=self._worker, args=(mode, target), daemon=True).start()

    def detect(self, t):
        if re.match(r"^https?://.+\.(jpg|jpeg|png|webp|gif)(\?.*)?$", t, re.I):
            return "PHOTO"
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", t) or re.fullmatch(r"[0-9a-fA-F:]{3,}:[0-9a-fA-F:]+", t):
            return "IP"
        if re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", t):
            return "MAIL"
        if re.fullmatch(r"\+?[\d\s\-\(\)]{7,}", t):
            return "PHONE"
        if re.fullmatch(r"([a-z0-9-]+\.)+[a-z]{2,}", t, re.I):
            return "DOMAIN"
        if t.startswith("@"):
            return "TG"
        return "USER"

    def _worker(self, mode, t):
        try:
            {"PHONE": self.scan_phone, "TG": self.scan_tg, "USER": self.scan_user,
             "DOMAIN": self.scan_domain, "IP": self.scan_ip, "MAIL": self.scan_mail,
             "PHOTO": self.scan_photo}[mode](t)
        except Exception as e:
            self.log(f"[X] Ошибка: {e}", "r")
        finally:
            self.log("[*] Готово.\n", "d")
            self.busy = False
            self.after(0, lambda: self.go.config(state="normal", text="▶ SCAN"))
            self.after(0, self.entry.focus_set)

    def row(self, k, v, tag="w"):
        self.log(f"  {k:<16}: {v}", tag)

    def _engines(self, query):
        for name, tpl in ENGINES:
            self.row(name, tpl.format(requests.utils.quote(query)), "c")

    # ---------- ТЕЛЕФОН ----------
    def scan_phone(self, raw):
        if not HAS_PN:
            self.log("[X] Установите: pip install phonenumbers", "r")
            return
        num = raw if raw.startswith("+") else "+" + re.sub(r"\D", "", raw)
        try:
            p = phonenumbers.parse(num, None)
        except phonenumbers.NumberParseException as e:
            self.log(f"[X] Не удалось разобрать номер: {e}. Вводите в формате +79991234567", "r")
            return
        self.log("[+] Анализ номера (libphonenumber)", "h")
        valid = phonenumbers.is_valid_number(p)
        self.row("Валиден", "ДА" if valid else "НЕТ", "g" if valid else "r")
        self.row("Международный", phonenumbers.format_number(p, phonenumbers.PhoneNumberFormat.INTERNATIONAL))
        self.row("E.164", phonenumbers.format_number(p, phonenumbers.PhoneNumberFormat.E164))
        self.row("Национальный", phonenumbers.format_number(p, phonenumbers.PhoneNumberFormat.NATIONAL))
        self.row("Страна/регион", geocoder.description_for_number(p, "ru") or "—")
        self.row("Код региона", phonenumbers.region_code_for_number(p) or "—")
        self.row("Оператор (ориг.)", carrier.name_for_number(p, "ru") or "—")
        types = {0: "Стационарный", 1: "Мобильный", 2: "Фикс/Моб", 3: "Бесплатный",
                 4: "Премиум", 6: "VoIP", 99: "Неизвестно"}
        self.row("Тип линии", types.get(phonenumbers.number_type(p), "Другое"))
        self.row("Часовые пояса", ", ".join(timezone.time_zones_for_number(p)) or "—")
        self.log("\n[+] Присутствие в мессенджерах (открытые ссылки)", "h")
        d = re.sub(r"\D", "", num)
        self.row("WhatsApp", f"https://wa.me/{d}", "c")
        self.row("Telegram", f"https://t.me/+{d}", "c")
        self.row("Viber", f"viber://add?number={d}", "c")
        self.log("\n[+] Прямой поиск в соцсетях по номеру", "h")
        nat = phonenumbers.format_number(p, phonenumbers.PhoneNumberFormat.NATIONAL)
        for net in PHONE_SOCIAL_NETS:
            q = f'site:{net} "{num}" OR "{d}" OR "{nat}"'
            self.row(net, "https://www.google.com/search?q=" + requests.utils.quote(q), "c")
        self.log("  (те же запросы стоит повторить в Yandex ниже - он лучше индексирует VK/OK)", "d")
        self.log("\n[+] Проверка утечек по номеру (откройте вручную)", "h")
        for name, tpl in LEAK_SITES:
            self.row(name, tpl.format(requests.utils.quote(num)), "c")
        self.log("\n[+] Поисковые системы по номеру", "h")
        self._engines(f'"{num}"')
        self.log("\n[i] Имя владельца по номеру в открытых данных напрямую не определяется.", "y")
        self.log("    Ссылки выше ищут упоминания номера в проиндексированных страницах соцсетей.", "y")

    # ---------- TELEGRAM ----------
    def scan_tg(self, raw):
        u = raw.lstrip("@").strip()
        if not re.fullmatch(r"[A-Za-z0-9_]{4,32}", u):
            self.log("[X] Некорректный username (5–32 символа: латиница, цифры, _).", "r")
            return
        self.log(f"[*] Запрос публичной страницы t.me/{u} ...", "d")
        r = requests.get(f"https://t.me/{u}", headers=UA, timeout=12)
        html = r.text
        meta = lambda p: (re.search(r'<meta property="og:%s" content="(.*?)"' % p, html, re.S) or [None, None])[1]
        title, desc, img = meta("title"), meta("description"), meta("image")
        import html as H
        title = H.unescape(title) if title else None
        desc = H.unescape(desc) if desc else None
        if not title or title.strip() == f"Telegram: Contact @{u}":
            self.log(f"[-] @{u} — публичного профиля не найдено (не существует или скрыт).", "r")
            return
        self.log(f"[+] @{u} НАЙДЕН", "g")
        self.row("Имя / название", title)
        self.row("Описание (bio)", (desc or "—").replace("\n", " "))
        if img:
            self.row("Аватар", img, "c")
        ext = re.search(r'tgme_page_extra">(.*?)<', html)
        if ext:
            self.row("Доп. инфо", H.unescape(ext.group(1)))
            self.row("Тип", "Канал/группа" if re.search(r"subscribers|members", ext.group(1)) else "Пользователь/бот")
        self.row("Ссылка", f"https://t.me/{u}", "c")
        self.log("\n[*] Проверяю этот ник на других платформах (нажмите USERNAME для полного скана)...", "d")
        self.scan_user(u, quiet=True)

    # ---------- USERNAME ----------
    def scan_user(self, raw, quiet=False):
        u = raw.lstrip("@").strip()
        if not u or " " in u:
            self.log("[X] Некорректный username.", "r")
            return
        self.log(f"[*] Сканирую {len(SITES)} платформ (параллельно) ...", "d")
        found, manual, errors = [], [], []

        def _title(html):
            t = re.search(r"<title>(.*?)</title>", html, re.S)
            return t.group(1).strip() if t else ""

        def check(site):
            name, tpl, kind, marker = site
            url = tpl.format(u)

            if name == "Instagram":
                try:
                    r = requests.get(url, headers=UA, timeout=10, allow_redirects=True)
                except Exception:
                    return name, url, "err"
                if r.status_code == 404:
                    return name, url, "no"
                title = _title(r.text)
                if r.status_code != 200 or not title:
                    return name, url, "manual"
                if "page not found" in title.lower() or "instagram" not in title.lower():
                    return name, url, "no"
                return name, url, "yes"

            if name == "TikTok":
                try:
                    r = requests.get(url, headers=UA, timeout=10, allow_redirects=True)
                except Exception:
                    return name, url, "err"
                title = _title(r.text)
                if r.status_code != 200 or not title:
                    return name, url, "manual"
                if "not found" in title.lower() or "tiktok" not in title.lower():
                    return name, url, "no"
                return name, url, "yes"

            if kind == "u":
                return name, url, "manual"
            try:
                r = requests.get(url, headers=UA, timeout=8, allow_redirects=True)
            except Exception:
                return name, url, "err"
            if r.status_code != 200:
                return name, url, "no"
            if kind == "n" and marker.format(u).lower() in r.text.lower():
                return name, url, "no"
            # редирект на главную/другую страницу = профиля нет
            if r.history and u.lower() not in r.url.lower():
                return name, url, "no"
            return name, url, "yes"

        with ThreadPoolExecutor(max_workers=20) as ex:
            futs = [ex.submit(check, s) for s in SITES]
            for f in as_completed(futs):
                name, url, st = f.result()
                if st == "yes":
                    found.append((name, url))
                    self.log(f"  [+] {name:<16} {url}", "g")
                elif st == "manual":
                    manual.append((name, url))
                elif st == "err":
                    errors.append(name)

        checked = len(SITES) - len(manual) - len(errors)
        self.log(f"\n[+] Найдено профилей: {len(found)} (проверено автоматически: {checked})", "c")
        if manual:
            self.log("\n[~] Эти сайты блокируют ботов - проверьте вручную:", "y")
            for name, url in sorted(manual):
                self.log(f"  [~] {name:<16} {url}", "c")
        if errors:
            self.log(f"\n[?] Нет ответа от: {', '.join(errors)}", "d")
        self.log("[i] Совпадение ника не доказывает, что это один человек - сверяйте фото, bio, ссылки.", "y")
        if not quiet:
            self.log("\n[+] Поиск ника в поисковых системах", "h")
            self._engines(f'"{u}"')

    # ---------- IP ----------
    def _ip_geo(self, ip):
        fields = "status,message,country,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
        r = requests.get(f"http://ip-api.com/json/{ip}", params={"fields": fields, "lang": "ru"}, timeout=10).json()
        if r.get("status") != "success":
            self.log(f"[X] {r.get('message', 'ошибка')}", "r")
            return None
        self.log("[+] Геолокация и провайдер", "h")
        self.row("IP", r["query"])
        self.row("Страна", r["country"])
        self.row("Регион/город", f'{r["regionName"]}, {r["city"]} {r["zip"]}')
        self.row("Координаты", f'{r["lat"]}, {r["lon"]}  (точность ~ город)')
        self.row("Часовой пояс", r["timezone"])
        self.row("Провайдер", r["isp"])
        self.row("Организация", r["org"] or "—")
        self.row("AS", f'{r["as"]}')
        self.row("Reverse DNS", r["reverse"] or "—")
        self.row("Мобильная сеть", "да" if r["mobile"] else "нет")
        self.row("VPN/Proxy", "ДА" if r["proxy"] else "нет", "r" if r["proxy"] else "g")
        self.row("Хостинг/ЦОД", "ДА" if r["hosting"] else "нет", "y" if r["hosting"] else "g")
        self.row("Карта", f'https://www.google.com/maps?q={r["lat"]},{r["lon"]}', "c")
        return r

    def scan_ip(self, raw):
        target = raw.strip()
        ip = target
        if not re.fullmatch(r"[0-9a-fA-F:.]+", target):
            try:
                ip = socket.gethostbyname(target)
                self.log(f"[+] DNS: {target} → {ip}", "g")
            except socket.gaierror:
                self.log("[X] Не удалось резолвить домен.", "r")
                return
        if not self._ip_geo(ip):
            return
        self.log("\n[+] Внешние сервисы", "h")
        self.row("Shodan", f"https://www.shodan.io/host/{ip}", "c")
        self.row("AbuseIPDB", f"https://www.abuseipdb.com/check/{ip}", "c")
        self.row("VirusTotal", f"https://www.virustotal.com/gui/ip-address/{ip}", "c")
        self.log("[i] По IP определяется провайдер и примерный город, но не личность и не адрес.", "y")

    # ---------- ДОМЕН ----------
    def scan_domain(self, raw):
        domain = raw.strip().lower()
        domain = re.sub(r"^https?://", "", domain).split("/")[0]
        if not re.fullmatch(r"([a-z0-9-]+\.)+[a-z]{2,}", domain):
            self.log("[X] Некорректный домен. Пример: example.com", "r")
            return

        self.log("[+] WHOIS", "h")
        if HAS_WHOIS:
            try:
                w = whois.whois(domain)
                ns = w.name_servers
                status = w.status
                self.row("Регистратор", w.registrar or "—")
                self.row("Дата регистрации", str(w.creation_date) if w.creation_date else "—")
                self.row("Дата окончания", str(w.expiration_date) if w.expiration_date else "—")
                self.row("Обновлён", str(w.updated_date) if w.updated_date else "—")
                self.row("Name servers", ", ".join(ns) if isinstance(ns, (list, set)) else str(ns or "—"))
                self.row("Статус", ", ".join(status) if isinstance(status, list) else str(status or "—"))
            except Exception as e:
                self.log(f"  WHOIS недоступен: {e}", "y")
        else:
            self.log("  Для WHOIS установите: pip install python-whois", "y")

        self.log("\n[+] DNS-записи", "h")
        ip = None
        try:
            ip = socket.gethostbyname(domain)
            self.row("A", ip, "g")
        except Exception:
            self.row("A", "не резолвится", "r")
        if HAS_DNS:
            for rtype in ["AAAA", "MX", "NS", "TXT", "CNAME"]:
                try:
                    answers = dns.resolver.resolve(domain, rtype, lifetime=6)
                    vals = ", ".join(str(a).strip('"') for a in answers)
                    self.row(rtype, vals)
                except Exception:
                    pass
        else:
            self.log("  Для MX/NS/TXT установите: pip install dnspython", "y")

        self.log("\n[+] Поддомены (по сертификатам, crt.sh)", "h")
        try:
            r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", headers=UA, timeout=15)
            subs = set()
            for item in r.json():
                for n in item.get("name_value", "").split("\n"):
                    n = n.strip().lower()
                    if n and "*" not in n and n.endswith(domain):
                        subs.add(n)
            subs = sorted(subs)
            self.row("Найдено", len(subs), "c")
            for s in subs[:40]:
                self.log(f"  - {s}", "g")
            if len(subs) > 40:
                self.log(f"  ... и ещё {len(subs) - 40}", "d")
        except Exception as e:
            self.log(f"  crt.sh недоступен: {e}", "y")

        if ip:
            self.log("")
            self._ip_geo(ip)

        self.log("\n[+] Внешние сервисы", "h")
        self.row("Утечки (HIBP)", f"https://haveibeenpwned.com/DomainSearch/{domain}", "c")
        self.row("Wayback Machine", f"https://web.archive.org/web/*/{domain}", "c")
        self.row("VirusTotal", f"https://www.virustotal.com/gui/domain/{domain}", "c")
        self.row("SecurityTrails", f"https://securitytrails.com/domain/{domain}/dns", "c")
        self.row("BuiltWith", f"https://builtwith.com/{domain}", "c")

    # ---------- ФОТО (обратный поиск) ----------
    def scan_photo(self, raw):
        url = raw.strip()
        if not re.match(r"^https?://", url):
            self.log("[X] Нужна прямая ссылка на изображение (https://.../photo.jpg).", "r")
            self.log("    Локальный файл сначала загрузите на imgbb.com или postimages.org и скопируйте ссылку.", "y")
            return
        q = requests.utils.quote(url, safe="")
        self.log("[+] Обратный поиск изображения", "h")
        self.row("Исходное фото", url, "c")
        self.row("Google Lens", f"https://lens.google.com/uploadbyurl?url={q}", "c")
        self.row("Yandex Images", f"https://yandex.com/images/search?rpt=imageview&url={q}", "c")
        self.row("Bing Visual", f"https://www.bing.com/images/search?view=detailv2&iss=sbiu&q=imgurl:{q}", "c")
        self.row("TinEye", f"https://tineye.com/search?url={q}", "c")
        self.log("\n[i] Это поиск ДРУГИХ КОПИЙ этого же изображения в интернете (соцсети, сайты,", "y")
        self.log("    стоковые базы) — а не распознавание лица и не поиск 'кто этот человек'.", "y")
        self.log("    Такой функции здесь нет и не будет: определение личности незнакомца по", "y")
        self.log("    лицу - это инструмент слежки без согласия, он не делается по запросу.", "y")

    # ---------- EMAIL ----------
    def scan_mail(self, mail):
        mail = mail.strip().lower()
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", mail):
            self.log("[X] Некорректный email.", "r")
            return
        h = hashlib.md5(mail.encode()).hexdigest()
        self.log("[+] Gravatar (публичный профиль)", "h")
        r = requests.get(f"https://gravatar.com/{h}.json", headers=UA, timeout=10)
        if r.status_code == 200:
            try:
                e = r.json()["entry"][0]
                self.row("Имя", e.get("displayName", "—"), "g")
                self.row("Ник", e.get("preferredUsername", "—"))
                self.row("Локация", e.get("currentLocation", "—"))
                self.row("Профиль", e.get("profileUrl", "—"), "c")
                for a in e.get("accounts", []):
                    self.row("Аккаунт", f'{a.get("shortname")}: {a.get("url")}', "c")
            except Exception:
                self.log("  профиль найден, разбор не удался", "y")
        else:
            self.log("  Публичного Gravatar-профиля нет.", "d")
        user, domain = mail.split("@")
        self.log("\n[+] Домен и ник", "h")
        self.row("Домен", domain)
        try:
            self.row("IP домена", socket.gethostbyname(domain))
        except Exception:
            self.row("IP домена", "не резолвится", "r")
        self.log(f"  Локальная часть '{user}' может быть ником → запускаю поиск...", "d")
        self.scan_user(user, quiet=True)
        self.log("\n[+] Проверка утечек (откройте вручную)", "h")
        for name, tpl in LEAK_SITES:
            self.row(name, tpl.format(requests.utils.quote(mail)), "c")
        self.row("Mozilla Monitor", "https://monitor.mozilla.org/", "c")
        self.log("\n[+] Поисковые системы по email", "h")
        self._engines(f'"{mail}"')


if __name__ == "__main__":
    App().mainloop()
