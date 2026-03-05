from django import template

register = template.Library()

VERDICT_COLORS = {
    "malicious": "#dc2626",
    "suspicious": "#d97706",
    "clean": "#16a34a",
    "unknown": "#6b7280",
    "error": "#991b1b",
}

VERDICT_BG = {
    "malicious": "#fef2f2",
    "suspicious": "#fffbeb",
    "clean": "#f0fdf4",
    "unknown": "#f9fafb",
    "error": "#fef2f2",
}

VERDICT_ICONS = {
    "malicious": "&#x1F534;",
    "suspicious": "&#x1F7E1;",
    "clean": "&#x1F7E2;",
    "unknown": "&#x26AA;",
    "error": "&#x274C;",
}


@register.filter
def verdict_color(value):
    return VERDICT_COLORS.get(str(value).lower(), "#6b7280")


@register.filter
def verdict_bg(value):
    return VERDICT_BG.get(str(value).lower(), "#f9fafb")


@register.filter
def verdict_icon(value):
    return VERDICT_ICONS.get(str(value).lower(), "&#x26AA;")


@register.filter
def join_list(value, sep=", "):
    if isinstance(value, list):
        return sep.join(str(v) for v in value if v)
    return value or ""
