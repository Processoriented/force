try:
    from .local import AUTH_CREDS, AUTH_HEADERS, AUTH_URL
except Exception as e:
    from .public import AUTH_URL, AUTH_HEADERS, AUTH_CREDS


AUTH_URL = AUTH_URL


AUTH_HEADERS = AUTH_HEADERS


AUTH_CREDS = AUTH_CREDS
