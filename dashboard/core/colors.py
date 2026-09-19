"""Semantic status colors shared by core (event tagging) and ui (labels,
banners, badges) -- Bootstrap's classic palette, theme-independent
because they're painted on their own backgrounds or used as accents.
Anything that needs to follow the light/dark theme uses ui.theme instead.
"""
GREEN = "#5cb85c"   # ok / production / low
ORANGE = "#f0ad4e"  # warning / elevated / medium
RED = "#d9534f"     # error / honeypot / high / destructive action
BLUE = "#5bc0de"    # informational
GREY = "#888888"    # muted / neutral / unknown
