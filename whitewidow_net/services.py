"""Catálogo de servicios reconocidos por dominio y filtro de ruido de la telemetría.

Solo se identifica el SERVICIO a partir del nombre de dominio (consulta DNS o SNI de TLS). No se ve contenido,
URLs ni rutas. "strong" = dominios que indican uso real del servicio; "weak" = dominios compartidos (miniaturas,
CDN) que se clasifican pero nunca disparan alertas.
"""
import ipaddress

CATEGORIES = {"Video", "Música", "Redes sociales", "Mensajería", "Juegos", "Videollamadas", "Adultos"}

SERVICES = {
    "youtube": {"label": "YouTube", "category": "Video",
                "strong": ("youtube.com", "youtu.be", "googlevideo.com", "youtubei.googleapis.com", "youtube-nocookie.com"),
                "weak": ("ytimg.com", "ggpht.com")},
    "netflix": {"label": "Netflix", "category": "Video",
                "strong": ("netflix.com", "netflix.net", "nflxvideo.net", "nflximg.net", "nflxext.com", "nflxso.net")},
    "disney": {"label": "Disney+", "category": "Video", "strong": ("disneyplus.com", "disney-plus.net", "bamgrid.com", "dssott.com")},
    "primevideo": {"label": "Prime Video", "category": "Video", "strong": ("primevideo.com", "aiv-cdn.net", "pv-cdn.net")},
    "max": {"label": "Max / HBO", "category": "Video", "strong": ("max.com", "hbomax.com")},
    "twitch": {"label": "Twitch", "category": "Video", "strong": ("twitch.tv", "ttvnw.net", "jtvnw.net")},
    "tiktok": {"label": "TikTok", "category": "Redes sociales", "strong": ("tiktok.com", "tiktokcdn.com", "tiktokv.com", "byteoversea.com", "musical.ly")},
    "instagram": {"label": "Instagram", "category": "Redes sociales", "strong": ("instagram.com", "cdninstagram.com")},
    "facebook": {"label": "Facebook", "category": "Redes sociales", "strong": ("facebook.com", "fbcdn.net", "facebook.net", "fb.com")},
    "whatsapp": {"label": "WhatsApp", "category": "Mensajería", "strong": ("whatsapp.com", "whatsapp.net")},
    "discord": {"label": "Discord", "category": "Mensajería", "strong": ("discord.com", "discord.gg", "discordapp.com", "discordapp.net")},
    "spotify": {"label": "Spotify", "category": "Música", "strong": ("spotify.com", "scdn.co", "spotifycdn.com")},
    "zoom": {"label": "Zoom", "category": "Videollamadas", "strong": ("zoom.us",)},
    "steam": {"label": "Steam", "category": "Juegos", "strong": ("steampowered.com", "steamcontent.com", "steamstatic.com", "steamcommunity.com")},
    "roblox": {"label": "Roblox", "category": "Juegos", "strong": ("roblox.com", "rbxcdn.com")},
    "epic": {"label": "Epic Games / Fortnite", "category": "Juegos", "strong": ("epicgames.com", "fortnite.com")},
    "adulto": {"label": "Sitio para adultos", "category": "Adultos",
               "strong": ("pornhub.com", "phncdn.com", "xvideos.com", "xvideos-cdn.com", "xnxx.com", "xhamster.com", "xhcdn.com",
                          "redtube.com", "youporn.com", "spankbang.com", "eporner.com", "tube8.com", "onlyfans.com", "chaturbate.com",
                          "stripchat.com", "beeg.com", "motherless.com", "porn.com", "brazzers.com", "tnaflix.com", "thumbzilla.com"),
               "tlds": ("xxx", "porn", "sex", "adult")},
}

SERVICES.update({
    "hulu": {"label": "Hulu", "category": "Video", "strong": ("hulu.com", "hulustream.com")},
    "paramount": {"label": "Paramount+", "category": "Video", "strong": ("paramountplus.com",)},
    "crunchyroll": {"label": "Crunchyroll", "category": "Video", "strong": ("crunchyroll.com",)},
    "vix": {"label": "ViX", "category": "Video", "strong": ("vix.com",)},
    "twitter": {"label": "X / Twitter", "category": "Redes sociales", "strong": ("twitter.com", "x.com", "twimg.com")},
    "reddit": {"label": "Reddit", "category": "Redes sociales", "strong": ("reddit.com", "redd.it", "redditmedia.com")},
    "snapchat": {"label": "Snapchat", "category": "Redes sociales", "strong": ("snapchat.com", "sc-cdn.net")},
    "pinterest": {"label": "Pinterest", "category": "Redes sociales", "strong": ("pinterest.com", "pinimg.com")},
    "linkedin": {"label": "LinkedIn", "category": "Redes sociales", "strong": ("linkedin.com", "licdn.com")},
    "telegram": {"label": "Telegram", "category": "Mensajería", "strong": ("telegram.org", "t.me")},
    "teams": {"label": "Microsoft Teams", "category": "Videollamadas", "strong": ("teams.microsoft.com",)},
    "chatgpt": {"label": "ChatGPT / OpenAI", "category": "Herramientas", "strong": ("openai.com", "chatgpt.com")},
    "playstation": {"label": "PlayStation Network", "category": "Juegos", "strong": ("playstation.net", "playstation.com")},
    "xbox": {"label": "Xbox Live", "category": "Juegos", "strong": ("xboxlive.com", "xbox.com")},
    "nintendo": {"label": "Nintendo", "category": "Juegos", "strong": ("nintendo.net", "nintendo.com")},
    "minecraft": {"label": "Minecraft", "category": "Juegos", "strong": ("minecraft.net", "mojang.com")},
    "amazon": {"label": "Amazon", "category": "Compras", "strong": ("amazon.com", "amazon.com.mx")},
    "mercadolibre": {"label": "Mercado Libre", "category": "Compras", "strong": ("mercadolibre.com", "mercadolibre.com.mx", "mercadolibre.com.ar")},
})
CATEGORIES.update({"Herramientas", "Compras"})

# Servicios que generan alerta por defecto cuando se ve actividad (se cambia en Actividad o en config.json).
DEFAULT_WATCH = ("youtube", "netflix", "adulto")


def _matches(domain: str, suffixes) -> bool:
    return any(domain == s or domain.endswith("." + s) for s in suffixes)


def classify_domain(domain: str, custom=()):
    """Devuelve {'key','label','category','strong'} o None si el dominio no pertenece a un servicio del catálogo.
    `custom`: reglas del usuario [{'key','label','pattern'}]; el patrón coincide con el dominio y todos sus subdominios."""
    d = (domain or "").lower().rstrip(".")
    if not d or "." not in d:
        return None
    for c in custom:
        pat = (c.get("pattern") or "").lower().strip(".")
        if pat and (d == pat or d.endswith("." + pat)):
            return {"key": c["key"], "label": c["label"], "category": "Personalizado", "strong": True}
    tld = d.rsplit(".", 1)[-1]
    for key, s in SERVICES.items():
        if _matches(d, s["strong"]) or tld in s.get("tlds", ()):
            return {"key": key, "label": s["label"], "category": s["category"], "strong": True}
        if _matches(d, s.get("weak", ())):
            return {"key": key, "label": s["label"], "category": s["category"], "strong": False}
    return None


def watch_options():
    """Lista para la interfaz: [{'key','label','category'}]."""
    return [{"key": k, "label": s["label"], "category": s["category"]} for k, s in SERVICES.items()]


# ---- ruido de la telemetría del equipo ----
NOISE_PORTS = {53, 67, 68, 123, 137, 138, 546, 547, 1900, 5353}


def _non_public(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_unspecified or a.is_reserved or ip.endswith(".255")


def is_noise(conn: dict) -> bool:
    """True para conexiones que no dicen nada del uso real: escuchas locales, LAN/multicast, DNS, NTP, DHCP, mDNS, SSDP, NetBIOS."""
    if conn.get("direction") == "listen":
        return True
    raddr = conn.get("raddr") or ""
    if not raddr or _non_public(raddr):
        return True
    return (conn.get("rport") or 0) in NOISE_PORTS


# ---- agrupación para la interfaz: "dominio o app" sin repeticiones
_MULTI_TLD = {"com.mx", "org.mx", "gob.mx", "edu.mx", "net.mx", "co.uk", "com.br", "com.ar", "com.co", "co.jp", "com.au", "co.nz", "com.pe", "com.cl"}
_INFRA_SUFFIX = ("arpa", "local", "localdomain", "lan", "home", "internal", "ntp.org", "msftconnecttest.com", "msftncsi.com", "gstatic.com",
                 "captive.apple.com", "detectportal.firefox.com", "connectivity-check.ubuntu.com", "ubuntu.com", "snapcraft.io", "mozilla.net", "mozilla.com")


def e2ld(domain: str) -> str:
    """Dominio registrable aproximado: a.b.ejemplo.com -> ejemplo.com (reconoce sufijos como com.mx)."""
    p = (domain or "").lower().rstrip(".").split(".")
    if len(p) <= 2:
        return ".".join(p)
    return ".".join(p[-3:]) if ".".join(p[-2:]) in _MULTI_TLD else ".".join(p[-2:])


def is_infra(domain: str) -> bool:
    """Dominios de infraestructura/conectividad que no dicen nada del uso (resolución inversa, mDNS, comprobaciones de red, NTP)."""
    d = (domain or "").lower().rstrip(".")
    return not d or "." not in d or any(d == x or d.endswith("." + x) for x in _INFRA_SUFFIX) or d.startswith("_")


def group_for(domain: str, custom=()):
    """(clave, etiqueta, tipo) para agrupar visitas: servicio conocido -> app; otro -> dominio registrable."""
    svc = classify_domain(domain, custom)
    if svc:
        return svc["key"], svc["label"], "app"
    g = e2ld(domain)
    return g, g, "dominio"
