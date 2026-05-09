# UVScanX seed API documentation snippets

These snippets are intentionally small and cite the official documentation families used by the
upgrade. The `uvscanx rules extract` command can replace this with live OpenAI-compatible
extraction output when `OPENAI_API_KEY` is configured.

## OpenSSL SSL_read / SSL_write

`SSL_read` and `SSL_write` return a positive value on success. A return value of 0 or a negative
value means the operation did not complete successfully and callers should handle it with
`SSL_get_error` as appropriate.

## OpenSSL SSL_get_peer_cert_chain

`SSL_get_peer_cert_chain` can return NULL when no certificate was presented, no connection was
established, or the chain is unavailable. Callers must check for NULL before dereferencing.

## OpenSSL RAND_pseudo_bytes

`RAND_pseudo_bytes` is deprecated in modern OpenSSL. Prefer stronger supported random byte APIs.

## libpcap pcap_activate

`pcap_activate` returns 0 on success without warnings, positive values on success with warnings,
and negative values on error. Therefore only negative return values should be treated as errors.

## SQLite sqlite3_open

Whether or not opening succeeds, resources associated with a database connection handle should be
released with `sqlite3_close` when no longer needed.


## Expanded RAG-backed libraries

The persistent API-usage knowledge base under `data/rag/api_usage/` adds local retrieval context
for libcurl, libxml2, mbedTLS, wolfSSL, uClibc/glibc, libupnp, OpenSSH, dnsmasq, and dropbear.
Library-style entries can become active deterministic checker rules. Application components such as
dnsmasq and dropbear are stored for TPC/version identification and manual review context unless a
concrete public or internal API rule is justified by symbol evidence.
