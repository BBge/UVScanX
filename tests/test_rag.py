from uvscanx.rag import active_rules_from_rag, list_libraries, search


def test_rag_lists_requested_components():
    libs = {r["library"] for r in list_libraries()}
    for name in {"libcurl", "libxml2", "mbedTLS", "wolfSSL", "OpenSSH", "uClibc / glibc", "libupnp", "dnsmasq", "dropbear"}:
        assert name in libs


def test_rag_search_and_active_rules():
    hits = search("curl_easy_perform")
    assert hits and hits[0]["library"] == "libcurl"
    rules = active_rules_from_rag()
    assert any(r["api"] == "curl_easy_perform" for r in rules["return_value"])
    assert any(r["open_api"] == "xmlReadFile" and r["close_api"] == "xmlFreeDoc" for r in rules["resource_lifecycle"])
    # Application components are retained as RAG context but not converted to checker rules.
    assert not any(r.get("library") == "dnsmasq" for sec in ("return_value", "argument", "causality", "deprecated", "resource_lifecycle") for r in rules[sec])


def test_rag_index_build_and_search(tmp_path):
    from uvscanx.rag import build_index, search_index

    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "libfoo.md").write_text("libfoo_open returns NULL on failure. Call libfoo_close to release handles.", encoding="utf-8")
    out = tmp_path / "index"
    manifest = build_index(docs, out, chunk_size=80, overlap=10)
    assert manifest["num_documents"] == 1
    assert manifest["num_chunks"] >= 1
    hits = search_index("libfoo_close", out)
    assert hits and hits[0]["chunk"]["relative_path"] == "libfoo.md"
