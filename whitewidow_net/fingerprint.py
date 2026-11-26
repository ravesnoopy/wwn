"""Huellas pasivas: tipo de dispositivo y SO estimados a partir de servicios anunciados (mDNS/SSDP) y DHCP.
Todo resultado es una ESTIMACIÓN, nunca una confirmación."""

SERVICE_HINTS = [
    ("_airplay", "Apple TV / AirPlay"), ("_raop", "Altavoz / Apple TV (AirPlay)"), ("_googlecast", "Chromecast / Google TV"),
    ("_androidtvremote", "Android TV"), ("_amzn-wplay", "Amazon Fire TV / Echo"), ("_spotify-connect", "Altavoz / TV con Spotify"),
    ("_ipp", "Impresora"), ("_printer", "Impresora"), ("_pdl-datastream", "Impresora"), ("_scanner", "Escáner"),
    ("_hap", "Accesorio HomeKit"), ("_homekit", "Accesorio HomeKit"), ("_hue", "Philips Hue Bridge"), ("_matter", "Dispositivo Matter"),
    ("_esphomelib", "Dispositivo IoT (ESPHome)"), ("_apple-mobdev", "iPhone / iPad"), ("_companion-link", "Dispositivo Apple"),
    ("_smb", "PC / NAS"), ("_afpovertcp", "Mac / NAS"), ("_workstation", "PC Linux"),
]
SSDP_HINTS = [("internetgatewaydevice", "Router / gateway"), ("mediarenderer", "TV / reproductor multimedia"),
              ("mediaserver", "Servidor multimedia / NAS"), ("printer", "Impresora"), ("roku", "Roku")]
DHCP_FP = {"1,121,3,6,15,119,252": "macOS / iOS (estimado)", "1,3,6,15,119,252": "macOS / iOS (estimado)",
           "1,15,3,6,44,46,47,31,33,121,249,43": "Windows (estimado)", "1,3,6,15,26,28,51,58,59,43": "Android (estimado)"}


def hint_from_services(services):
    low = [x.lower() for x in services]
    for key, label in SERVICE_HINTS:
        if any(x == key or x.startswith(key) for x in low):
            return label
    for x in low:
        for key, label in SSDP_HINTS:
            if x.startswith(("upnp:", "server:")) and key in x:
                return label
    return ""


def os_from_dhcp(vendor_class, fp):
    v = (vendor_class or "").lower()
    if v.startswith("msft"):
        return "Windows (estimado)"
    if v.startswith("android-dhcp"):
        return "Android (estimado)"
    if v.startswith("dhcpcd"):
        return "Linux (estimado)"
    if v.startswith("udhcp"):
        return "Linux embebido / IoT (estimado)"
    return DHCP_FP.get(fp or "", "")


def refine(dtype, os_guess, services, dhcp_vendor="", dhcp_fp=""):
    """Mejora una clasificación débil con los datos pasivos disponibles."""
    if dtype in ("Desconocido", None, "") or str(dtype).startswith("Móvil/tablet probable"):
        h = hint_from_services(services)
        if h:
            dtype = h
    if not os_guess:
        os_guess = os_from_dhcp(dhcp_vendor, dhcp_fp)
    return dtype, os_guess


# ---------------------------------------------------------------- categoría para el usuario
import json as _json
import re as _re

CATEGORY_CHOICES = ["Teléfono", "Tablet", "TV", "Computadora", "Consola", "Bocina / asistente", "Router", "Impresora", "IoT / Hogar", "Cámara", "Teléfono o tablet", "Sin identificar"]
ENDPOINT_CATEGORIES = ("Teléfono", "Tablet", "TV", "Computadora", "Consola", "Bocina / asistente", "Teléfono o tablet", "IoT / Hogar", "Cámara", "Impresora")
_SPEAKER_HOST = _re.compile(r"echo|alexa|homepod|sonos|nest[ _-]?(mini|hub|audio)|google[ _-]?home")
_CONSOLE_HOST = _re.compile(r"xbox|playstation|(^|[^a-z])ps[45]([^a-z0-9]|$)|nintendo|steamdeck")

_TV_HOST = _re.compile(r"(^|[^a-z])(tv|bravia|roku|chromecast|firetv|fire-tv|webos|tizen|androidtv|appletv|apple-tv|smarttv|shield)([^a-z]|$)|tv$")  # "SalaTV" también
_TABLET_HOST = _re.compile(r"ipad|tablet|galaxy[ _-]?tab|(^|[^a-z])tab[ _-]?[a-z]?\d|mipad|lenovo[ _-]?tb|kindle|matepad|surface[ _-]?go")
_PHONE_HOST = _re.compile(r"iphone|redmi|pixel|oneplus|poco|galaxy[ _-]?[sazm]\d|(^|[^a-z])phone([^a-z]|$)")
_PC_HOST = _re.compile(r"macbook|imac|mac[ _-]?mini|(^|[^a-z])mbp|desktop-|laptop-|thinkpad|ubuntu|debian|fedora|(^|[^a-z])pc([^a-z]|$)|windows")
_PHONE_VENDORS = ("xiaomi", "oneplus", "oppo", "vivo", "realme", "motorola", "honor", "huawei")
_PC_VENDORS = ("dell", "hewlett", "lenovo", "asustek", "micro-star", "gigabyte", "intel", "microsoft", "liteon", "azurewave")
_TV_VENDORS = ("roku", "vizio", "tcl", "hisense", "skyworth")


def _svc_has(svcs, *keys):
    return any(x.startswith(k) for x in svcs for k in keys)


def category(dev):
    """Categoría simple para la persona (Teléfono, Tablet, TV, Computadora, ...) con su motivo y confianza.
    `dev` es una fila de la tabla devices. Siempre es una estimación; user_type (elegido por la persona) manda."""
    try:
        svcs = [x.lower() for x in _json.loads(dev.get("services") or "[]")]
        ports = set(_json.loads(dev.get("ports") or "[]"))
    except (ValueError, TypeError):
        svcs, ports = [], set()
    host = (dev.get("hostname") or "").lower()
    vendor = (dev.get("vendor") or "").lower()
    osg = (dev.get("os_guess") or "").lower()
    dtype = (dev.get("dtype") or "").lower()
    if dev.get("user_type") in CATEGORY_CHOICES:
        return {"category": dev["user_type"], "basis": "elegida por ti", "confidence": "manual"}
    if dev.get("is_gateway"):
        return {"category": "Router", "basis": "es el gateway de la red", "confidence": "alta"}
    if dev.get("is_self"):
        return {"category": "Computadora", "basis": "este equipo", "confidence": "alta"}

    def r(cat, basis, conf):
        return {"category": cat, "basis": basis, "confidence": conf}

    if ports & {9100, 631} or _svc_has(svcs, "_ipp", "_printer", "_pdl-datastream", "_scanner") or "impresora" in dtype:
        return r("Impresora", "anuncia servicio de impresión", "alta")
    if 554 in ports or "cámara" in dtype:
        return r("Cámara", "transmite video (RTSP)", "media")
    if _svc_has(svcs, "_hap", "_homekit", "_hue", "_matter", "_esphomelib") or "espressif" in vendor:
        return r("IoT / Hogar", "accesorio doméstico inteligente", "alta" if svcs else "media")
    if _svc_has(svcs, "_androidtvremote", "_amzn-wplay") or _svc_has(svcs, "upnp:mediarenderer") or "roku" in " ".join(svcs):
        return r("TV", "anuncia control de TV / reproductor", "alta")
    if _svc_has(svcs, "_googlecast"):
        return r("TV", "anuncia Google Cast (Chromecast, TV o bocina)", "media")
    if _svc_has(svcs, "_airplay", "_raop"):
        if "apple" not in vendor:
            return r("TV", "anuncia AirPlay y no es de Apple (TV o bocina)", "media")
        if _TV_HOST.search(host):
            return r("TV", "Apple TV por su nombre", "alta")
    if _svc_has(svcs, "_apple-mobdev"):
        return r("Tablet" if _TABLET_HOST.search(host) else "Teléfono" if _PHONE_HOST.search(host) else "Teléfono o tablet", "iPhone/iPad (servicio móvil de Apple)", "alta")
    if _TABLET_HOST.search(host):
        return r("Tablet", "por su nombre", "alta")
    if _PHONE_HOST.search(host):
        return r("Teléfono", "por su nombre", "alta")
    if _TV_HOST.search(host):
        return r("TV", "por su nombre", "alta")
    if _PC_HOST.search(host):
        return r("Computadora", "por su nombre", "alta")
    if _CONSOLE_HOST.search(host) or any(v in vendor for v in ("nintendo", "sony interactive")):
        return r("Consola", "por su nombre o fabricante", "alta" if _CONSOLE_HOST.search(host) else "media")
    if _SPEAKER_HOST.search(host) or _svc_has(svcs, "_sonos", "_spotify-connect") or "sonos" in vendor:
        return r("Bocina / asistente", "por su nombre o servicios de audio", "media")
    if _svc_has(svcs, "_smb", "_afpovertcp", "_workstation", "netbios") or "pc / servidor" in dtype or "raspberry" in dtype or "máquina virtual" in dtype:
        return r("Computadora", "anuncia servicios de equipo de escritorio/servidor", "media")
    if osg.startswith("ios") or "android" in osg or host.startswith("android"):
        return r("Teléfono o tablet", "sistema móvil (iOS/Android)", "media")
    if "macos / ios" in osg:  # macOS e iOS comparten huella DHCP: no se puede separar sin más datos
        return r("Teléfono o tablet", "Apple (puede ser iPhone, iPad o Mac)", "baja")
    if "embebido" in osg or "iot" in dtype:
        return r("IoT / Hogar", "sistema embebido", "media")
    if "windows" in osg or "macos" in osg or "linux" in osg:
        return r("Computadora", "sistema de escritorio", "media")
    if any(v in vendor for v in _TV_VENDORS):
        return r("TV", f"fabricante {dev.get('vendor')}", "baja")
    if any(v in vendor for v in _PHONE_VENDORS):
        return r("Teléfono o tablet", f"fabricante {dev.get('vendor')}", "baja")
    if any(v in vendor for v in _PC_VENDORS):
        return r("Computadora", f"fabricante {dev.get('vendor')}", "baja")
    if dev.get("random_mac"):
        return r("Teléfono o tablet", "MAC privada (típica de móviles y tablets)", "baja")
    return r("Sin identificar", dev.get("vendor") or "sin pistas todavía", "baja")


# ---------------------------------------------------------------- nombre y "detectado como" siempre con texto
_VENDOR_NOISE = _re.compile(r"\b(inc|co|corp|corporation|ltd|llc|gmbh|technologies|technology|electronics|communications|international|limited|company|group)\b\.?,?", _re.I)
_GENERIC_HOST = _re.compile(r"^(localhost|unknown|\(null\)|\*|[0-9a-f]{12,}|[0-9a-f-]{32,})$")
_VENDOR_LABELS = (
    ("espressif", "Módulo IoT ESP32 / ESP8266"), ("tuya", "Dispositivo Tuya (enchufe o foco)"), ("raspberry", "Raspberry Pi"),
    ("nintendo", "Consola Nintendo"), ("sony interactive", "Consola PlayStation"), ("sonos", "Bocina Sonos"), ("amazon", "Amazon (Echo, Fire TV o Kindle)"),
    ("tp-link", "TP-Link (router, enchufe o cámara)"), ("xiaomi", "Xiaomi (teléfono, TV o aparato del hogar)"), ("samsung", "Samsung (teléfono, tablet o TV)"),
    ("lg elec", "LG (TV o teléfono)"), ("apple", "Apple (iPhone, iPad, Mac o Apple TV)"), ("google", "Google (Pixel, Nest o Chromecast)"),
    ("huawei", "Huawei (teléfono, tablet o router)"), ("hitron", "Router Hitron"), ("intel", "Computadora con tarjeta Intel"),
    ("microsoft", "Microsoft (PC, Surface o Xbox)"), ("realtek", "Computadora o aparato con chip Realtek"), ("liteon", "Laptop (módulo Lite-On)"),
    ("azurewave", "Laptop (módulo AzureWave)"), ("murata", "Teléfono o IoT (módulo Murata)"), ("hon hai", "Equipo con módulo Foxconn"),
    ("roku", "Roku"), ("vizio", "TV Vizio"), ("tcl", "TV TCL"), ("hisense", "TV Hisense"), ("motorola", "Teléfono Motorola"), ("oneplus", "Teléfono OnePlus"),
    ("oppo", "Teléfono OPPO"), ("vivo", "Teléfono vivo"), ("realme", "Teléfono realme"), ("honor", "Teléfono Honor"), ("dell", "Computadora Dell"),
    ("hewlett", "Computadora HP"), ("lenovo", "Lenovo (laptop o tablet)"), ("asustek", "ASUS (laptop, PC o router)"), ("micro-star", "Computadora MSI"),
)
_SERVICE_LABELS = (
    ("_googlecast", "Chromecast / Google TV / bocina Nest"), ("_androidtvremote", "Android TV / Google TV"), ("_amzn-wplay", "Amazon Fire TV / Echo"),
    ("_apple-mobdev", "iPhone / iPad"), ("_companion-link", "Dispositivo Apple"), ("_airplay", "Equipo con AirPlay"), ("_ipp", "Impresora de red"),
    ("_printer", "Impresora de red"), ("_hap", "Accesorio HomeKit"), ("_homekit", "Accesorio HomeKit"), ("_hue", "Puente Philips Hue"),
    ("_matter", "Dispositivo Matter"), ("_spotify-connect", "Bocina con Spotify Connect"), ("_smb", "PC o NAS con carpetas compartidas"),
)
_CATEGORY_LABELS = {"Teléfono": "Teléfono", "Tablet": "Tablet", "TV": "Smart TV / reproductor", "Computadora": "Computadora", "Consola": "Consola de juegos",
                    "Bocina / asistente": "Bocina o asistente de voz", "Router": "Router / gateway", "Impresora": "Impresora", "IoT / Hogar": "Dispositivo del hogar inteligente",
                    "Cámara": "Cámara IP", "Teléfono o tablet": "Teléfono o tablet", "Sin identificar": "Dispositivo en la red"}


def vendor_short(vendor):
    v = (vendor or "").strip()
    if not v or "aleatoria" in v.lower() or "administrada" in v.lower():
        return ""
    return _re.sub(r"\s+", " ", _VENDOR_NOISE.sub("", v)).strip(" ,.-").title()[:22]


def display_name(dev, cat=None):
    """Nombre legible que nunca queda vacío: etiqueta > nombre de red > "Fabricante Categoría ·XXXX"."""
    cat = cat or category(dev)["category"]
    label = (dev.get("label") or "").strip()
    if label:
        return label
    host = (dev.get("hostname") or "").strip().split(".")[0]
    if dev.get("is_self"):
        return f"Este equipo ({host})" if host else "Este equipo"
    if dev.get("is_gateway"):
        return f"Router{' ' + vendor_short(dev.get('vendor')) if vendor_short(dev.get('vendor')) else ''} (gateway)"
    if host and not _GENERIC_HOST.match(host.lower()):
        return host
    tail = (dev.get("mac") or "")[-5:].replace(":", "").upper() if ":" in (dev.get("mac") or "") else (dev.get("ip") or "").split(".")[-1]
    base = {"Sin identificar": "Dispositivo", "Teléfono o tablet": "Teléfono/Tablet"}.get(cat, cat)
    v = vendor_short(dev.get("vendor"))
    return f"{v + ' ' if v else ''}{base} ·{tail}"


def detected_as(dev, cat=None):
    """Descripción del posible dispositivo; nunca "desconocido"."""
    cat = cat or category(dev)["category"]
    try:
        svcs = [x.lower() for x in _json.loads(dev.get("services") or "[]")]
    except (ValueError, TypeError):
        svcs = []
    vendor = (dev.get("vendor") or "").lower()
    if dev.get("is_gateway"):
        return "Router / gateway de la red"
    if dev.get("is_self"):
        return "Este equipo (donde corre WhiteWidow)"
    if dev.get("user_type"):
        return _CATEGORY_LABELS.get(cat, cat)
    for key, text in _SERVICE_LABELS:
        if _svc_has(svcs, key):
            return text
    for key, text in _VENDOR_LABELS:
        if key in vendor:
            return text
    txt = _CATEGORY_LABELS.get(cat, "Dispositivo en la red")
    if cat == "Teléfono o tablet" and dev.get("random_mac"):
        txt += " (MAC privada)"
    return txt
