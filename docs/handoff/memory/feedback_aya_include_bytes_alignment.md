---
name: aya 0.13.1 needs 8-byte aligned ELF bytes
description: aya::Ebpf::load() rejects unaligned slices with "Invalid ELF header size or alignment"; include_bytes!() returns 1-byte aligned data and breaks it. Wrap in #[repr(C, align(8))] when embedding.
type: feedback
originSessionId: 621387c2-943d-4e98-9fe3-2fe6a8adf4f4
---
`aya::Ebpf::load(bytes)` requires `bytes` to be 8-byte aligned (it casts
to `*const Elf64_Ehdr` directly). `include_bytes!("foo.bpf.o")` returns
`&'static [u8; N]` with **alignment = 1**, so passing it to `Ebpf::load`
fails with `ParseError(ElfError(Error("Invalid ELF header size or
alignment")))`.

`fs::read(...)` works because `Vec<u8>` from the heap is naturally
aligned (allocators return ≥8-byte aligned memory).

**Why:** the alignment requirement isn't called out in aya's docs; the
error message ("Invalid ELF header size or alignment") sounds like a
malformed ELF, not a caller bug. Cost us a long bisection on M6.2
because we kept blaming the .bpf.o contents. The standalone
`fs::read` + `aya::Ebpf::load` test always succeeded on the same bytes
the agent's `include_bytes!` was failing on.

**How to apply:** when embedding a BPF object via `include_bytes!`, wrap
the bytes in an aligned newtype before handing the slice to aya:
```rust
#[repr(C, align(8))]
struct AlignedObject<const N: usize>([u8; N]);
static EBPF_OBJECT_ALIGNED: &AlignedObject<{ include_bytes!("...").len() }> =
    &AlignedObject(*include_bytes!("..."));
const EBPF_OBJECT: &[u8] = &EBPF_OBJECT_ALIGNED.0;
```

If aya later starts loading 1-byte-aligned slices, this wrap is
harmless. If you ever switch loaders (libbpf-rs, etc.), keep the wrap
unless you've confirmed the new loader doesn't care.
