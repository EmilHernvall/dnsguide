Translating the guide
=====================

The English version in [`docs/en/`](docs/en/) is the reference. Every other
language lives in its own directory next to it and mirrors its structure.

Adding a new language
---------------------

1. Pick the [BCP 47](https://www.w3.org/International/articles/language-tags/)
   code of the language, in lowercase with an optional region:
   `fr`, `es`, `de`, `pt-br`, `zh-hans`…
2. Copy the English directory:

   ```sh
   cp -r docs/en docs/<lang>
   ```

3. Translate `README.md` and each `chapterN.md`. Keep the same file names so
   that links between chapters keep working.
4. Update the language banner at the top of `docs/<lang>/README.md`, e.g.
   `> 🌐 **Français** · [Other languages](../../README.md#languages)`.
5. Add a row to the **Languages** table in the root [README.md](README.md).
6. Open a pull request.

Partial translations are welcome: mark them as `In progress` in the table and
leave the untranslated chapters in English until they are done.

Translation rules
-----------------

* **Do not translate code.** Rust snippets, identifiers (`BytePacketBuffer`,
  `read_qname`…), shell commands and command output stay as they are, so they
  match the shared code in [`examples/`](examples/). Comments inside code
  blocks may be translated.
* **Keep protocol terms recognisable.** On first use, give the English term
  alongside the translation, e.g. « résolveur de souche (*stub resolver*) ».
  Field and record names from the RFCs (`QNAME`, `RCODE`, `A`, `NS`, `CNAME`,
  `MX`, `AAAA`…) are never translated.
* **Keep links relative.** Link to other chapters with `chapterN.md` and to the
  samples with `../../examples/sampleN.rs`.
* **Stay in sync.** When a chapter changes in English, the commit or pull
  request should say so, so that translators can update their version. A
  translation may state at the top which English revision it is based on.

Code samples
------------

The samples in [`examples/`](examples/) are shared by every language and are
not duplicated. Changes to the code should be made there and reflected in the
English chapters first.
