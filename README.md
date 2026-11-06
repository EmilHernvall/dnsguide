Building a DNS server in Rust
=============================

A step-by-step guide to implementing a DNS server in Rust, starting from first
principles: parsing the DNS protocol, building a stub resolver, supporting more
record types, serving requests and finally resolving names recursively.

Languages
---------

| Language | Guide | Status |
|----------|-------|--------|
| English  | [docs/en](docs/en/README.md) | Original |
| Français | [docs/fr](docs/fr/README.md) | Complete |

Want to add a language? See [TRANSLATING.md](TRANSLATING.md).

Repository layout
-----------------

```
.
├── docs/
│   └── <lang>/          # one directory per language (BCP 47 code: en, fr, pt-br…)
│       ├── README.md    # introduction and table of contents
│       └── chapterN.md  # chapters 1 to 5
├── examples/
│   └── sampleN.rs       # code for each chapter, shared by all languages
├── Cargo.toml
└── TRANSLATING.md       # how to contribute a translation
```

Samples
-------

Each chapter has a corresponding sample in [`examples/`](examples/) which
contains the full code up to that point in the guide, named `sample1.rs`
through `sample5.rs`. These can be run using, for first chapter,
`cargo run --example sample1`.

Revision History
----------------

 * June 2020 - Fixed a security vulnerability in `read_qname` which allowed for
   a malicious packet to trigger an infinite loop. Modernized the code to
   conform to current rust practices, and fixed various ugly inefficiencies.
 * July 2016 - Initial version
