"""Network attacker ("fake Wi-Fi") demo: a TLS-blind man-in-the-middle TCP proxy.

See attack_lab/README.md, section "Network attacker demo". The proxy never holds the
server's TLS key and never terminates TLS: it only reads and rewrites raw TLS records.
"""
