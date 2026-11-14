from __future__ import annotations

import hashlib
import math
import mmap
import os
import tempfile
import re
from itertools import chain, islice
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable


BDVE_DEFAULT_STEP = 1_022_554
BDVE_DEFAULT_LENGTH = 311_610
BDVE_KNOWN_PROFILES = (
    (BDVE_DEFAULT_STEP, BDVE_DEFAULT_LENGTH),
    (102_303, 89_230),
    (819_183, 153_631),
    (144_241, 2_142),
    (808_940, 118_714),
    (488_065, 132_216),
    (717_098, 320_207),
    (766_386, 699_732),
)
MAX_DISCOVERY_STEP = 5_000_000

LogFn = Callable[[str], None]


class DecodeError(RuntimeError):
    pass


@dataclass(frozen=True)
class BdveFooter:
    start: int
    size: int
    cryptor_type: int
    version: int
    sha256: bytes


@dataclass(frozen=True)
class CryptorParams:
    step: int
    length: int
    key: int


@dataclass(frozen=True)
class Sample:
    pos: int
    size: int


@dataclass(frozen=True)
class Box:
    start: int
    size: int
    type: bytes
    header_size: int

    @property
    def content_start(self) -> int:
        return self.start + self.header_size

    @property
    def end(self) -> int:
        return self.start + self.size


def xor_bytes(data: bytes, key: int) -> bytes:
    return data.translate(bytes(value ^ key for value in range(256)))


def param_sha256(step: int, length: int, key: int) -> bytes:
    payload = step.to_bytes(4, "big") + length.to_bytes(4, "big") + bytes([key])
    return hashlib.sha256(payload).digest()


def parse_bdve_footer(data: bytes) -> BdveFooter | None:
    if len(data) < 68:
        return None

    bdve_size = int.from_bytes(data[-4:], "big")
    bdve_start = len(data) - bdve_size
    if (
        bdve_size < 16
        or bdve_start < 0
        or bdve_start + 8 > len(data)
        or data[bdve_start + 4 : bdve_start + 8] != b"bdve"
    ):
        return None

    cursor = bdve_start + 8
    end = bdve_start + bdve_size
    while cursor + 8 <= end:
        child_size = int.from_bytes(data[cursor : cursor + 4], "big")
        child_type = data[cursor + 4 : cursor + 8]
        if child_size < 8 or cursor + child_size > end:
            break

        if child_type == b"crpt" and child_size >= 48:
            payload = data[cursor + 8 : cursor + child_size]
            return BdveFooter(
                start=bdve_start,
                size=bdve_size,
                cryptor_type=int.from_bytes(payload[0:4], "big"),
                version=int.from_bytes(payload[4:8], "big"),
                sha256=payload[8:40],
            )

        cursor += child_size

    return None


def iter_boxes(data: bytes, start: int, end: int) -> Iterable[Box]:
    cursor = start
    while cursor + 8 <= end:
        size = int.from_bytes(data[cursor : cursor + 4], "big")
        box_type = data[cursor + 4 : cursor + 8]
        header_size = 8

        if size == 1:
            if cursor + 16 > end:
                return
            size = int.from_bytes(data[cursor + 8 : cursor + 16], "big")
            header_size = 16
        elif size == 0:
            size = end - cursor

        if size < header_size or cursor + size > end:
            return

        yield Box(cursor, size, box_type, header_size)
        cursor += size


def find_child(data: bytes, parent: Box, box_type: bytes) -> Box | None:
    for child in iter_boxes(data, parent.content_start, parent.end):
        if child.type == box_type:
            return child
    return None


def find_path(data: bytes, parent: Box, path: tuple[bytes, ...]) -> Box | None:
    current = parent
    for box_type in path:
        child = find_child(data, current, box_type)
        if child is None:
            return None
        current = child
    return current


def find_top_level(data: bytes, box_type: bytes) -> Box | None:
    for box in iter_boxes(data, 0, len(data)):
        if box.type == box_type:
            return box
    return None


def iter_box_candidates(data: bytes, box_type: bytes) -> Iterable[Box]:
    top_level = find_top_level(data, box_type)
    seen: set[int] = set()
    if top_level is not None:
        seen.add(top_level.start)
        yield top_level

    cursor = 0
    while True:
        marker = data.find(box_type, cursor)
        if marker < 0:
            return

        start = marker - 4
        cursor = marker + 1
        if start < 0 or start in seen:
            continue

        size = int.from_bytes(data[start:marker], "big")
        header_size = 8
        if size == 1:
            if start + 16 > len(data):
                continue
            size = int.from_bytes(data[start + 8 : start + 16], "big")
            header_size = 16
        elif size == 0:
            size = len(data) - start

        if size < header_size or start + size > len(data):
            continue

        seen.add(start)
        yield Box(start, size, box_type, header_size)


def read_u32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 4], "big")


def parse_stsz(data: bytes, box: Box) -> list[int]:
    offset = box.content_start
    if offset + 12 > box.end:
        raise DecodeError("Invalid stsz box.")

    sample_size = read_u32(data, offset + 4)
    sample_count = read_u32(data, offset + 8)
    if sample_size:
        return [sample_size] * sample_count

    sizes_start = offset + 12
    sizes_end = sizes_start + sample_count * 4
    if sizes_end > box.end:
        raise DecodeError("Invalid stsz sample table.")

    return [read_u32(data, sizes_start + index * 4) for index in range(sample_count)]


def parse_stsc(data: bytes, box: Box) -> list[tuple[int, int, int]]:
    offset = box.content_start
    if offset + 8 > box.end:
        raise DecodeError("Invalid stsc box.")

    entry_count = read_u32(data, offset + 4)
    entries_start = offset + 8
    entries_end = entries_start + entry_count * 12
    if entries_end > box.end:
        raise DecodeError("Invalid stsc table.")

    entries = []
    for index in range(entry_count):
        item = entries_start + index * 12
        entries.append(
            (
                read_u32(data, item),
                read_u32(data, item + 4),
                read_u32(data, item + 8),
            )
        )
    return entries


def parse_chunk_offsets(data: bytes, box: Box) -> list[int]:
    offset = box.content_start
    if offset + 8 > box.end:
        raise DecodeError("Invalid chunk offset box.")

    entry_count = read_u32(data, offset + 4)
    item_size = 8 if box.type == b"co64" else 4
    offsets_start = offset + 8
    offsets_end = offsets_start + entry_count * item_size
    if offsets_end > box.end:
        raise DecodeError("Invalid chunk offset table.")

    offsets = []
    for index in range(entry_count):
        item = offsets_start + index * item_size
        offsets.append(int.from_bytes(data[item : item + item_size], "big"))
    return offsets


def parse_video_samples(full_xor_payload: bytes) -> list[Sample]:
    found_moov = False
    for moov in iter_box_candidates(full_xor_payload, b"moov"):
        found_moov = True
        samples = parse_video_samples_from_moov(full_xor_payload, moov)
        if samples is not None:
            return samples

    if not found_moov:
        raise DecodeError("Could not find moov box after preliminary decode.")

    raise DecodeError("Could not find a video sample table.")


def parse_video_samples_from_moov(data: bytes, moov: Box) -> list[Sample] | None:
    for trak in iter_boxes(data, moov.content_start, moov.end):
        if trak.type != b"trak":
            continue

        hdlr = find_path(data, trak, (b"mdia", b"hdlr"))
        if hdlr is None:
            continue

        handler = data[hdlr.content_start + 8 : hdlr.content_start + 12]
        if handler != b"vide":
            continue

        stbl = find_path(data, trak, (b"mdia", b"minf", b"stbl"))
        if stbl is None:
            continue

        stsz = find_child(data, stbl, b"stsz")
        stsc = find_child(data, stbl, b"stsc")
        stco = find_child(data, stbl, b"stco") or find_child(data, stbl, b"co64")
        if stco is None and stsz is not None and stsc is not None:
            for cand_key in set([data[0], 0xEF]):
                marker = bytes(b ^ cand_key for b in b"stco")
                pos = data.find(marker, stbl.content_start, stbl.end)
                if pos > 4:
                    bsize = int.from_bytes(bytes(b ^ cand_key for b in data[pos-4:pos]), "big")
                    if 8 <= bsize <= len(data) - pos + 4:
                        dchunk = bytes(b ^ cand_key for b in data[pos-4 : pos-4+bsize])
                        dstco = Box(0, bsize, b"stco", 8)
                        sizes = parse_stsz(data, stsz)
                        stsc_entries = parse_stsc(data, stsc)
                        chunk_offsets = parse_chunk_offsets(dchunk, dstco)
                        return build_samples(sizes, stsc_entries, chunk_offsets)
        if stsz is None or stsc is None or stco is None:
            continue

        sizes = parse_stsz(data, stsz)
        stsc_entries = parse_stsc(data, stsc)
        chunk_offsets = parse_chunk_offsets(data, stco)
        return build_samples(sizes, stsc_entries, chunk_offsets)

    return None


def build_samples(
    sample_sizes: list[int],
    stsc_entries: list[tuple[int, int, int]],
    chunk_offsets: list[int],
) -> list[Sample]:
    samples = []
    sample_index = 0
    stsc_index = 0

    for chunk_number, chunk_offset in enumerate(chunk_offsets, start=1):
        while (
            stsc_index + 1 < len(stsc_entries)
            and stsc_entries[stsc_index + 1][0] <= chunk_number
        ):
            stsc_index += 1

        samples_per_chunk = stsc_entries[stsc_index][1]
        cursor = chunk_offset
        for _ in range(samples_per_chunk):
            if sample_index >= len(sample_sizes):
                return samples
            size = sample_sizes[sample_index]
            samples.append(Sample(cursor, size))
            cursor += size
            sample_index += 1

    return samples


def score_h264_sample(sample: bytes) -> int:
    offset = 0
    score = 0
    nal_count = 0
    limit = len(sample)

    while offset + 5 <= limit and nal_count < 10:
        nal_size = int.from_bytes(sample[offset : offset + 4], "big")
        if nal_size <= 0 or nal_size > limit - offset - 4:
            score -= 5
            break

        nal_type = sample[offset + 4] & 0x1F
        if nal_type in {1, 5, 6, 7, 8, 9}:
            score += 4
        elif 1 <= nal_type <= 23:
            score += 1
        else:
            score -= 3

        offset += 4 + nal_size
        nal_count += 1
        if offset == limit:
            score += 6
            break

    if nal_count == 0:
        score -= 10

    return score


_verified_profiles: dict[bytes, CryptorParams] = {}


def discover_adts_params(payload, key, digest, *, split_headers=False):
    """Bracket XOR transitions using consecutive AAC frame sync bytes."""
    starts = []
    ends = []
    pos = previous = 0
    encrypted = True
    previous_size = None
    while pos + 7 <= len(payload) and len(starts) < 24:
        if payload[pos] not in (255, 255 ^ key):
            break
        mask = key if payload[pos] ^ key == 255 else 0
        raw = payload[pos:pos + 7]
        sizes = []
        # An XOR boundary may pass through the header, including its size field.
        for split in (range(7, 0, -1) if split_headers else (7,)):
            header = bytes(b ^ (mask if i < split else mask ^ key) for i, b in enumerate(raw))
            if header[1] & 0xF6 != 0xF0:
                continue
            size = ((header[3] & 3) << 11) | (header[4] << 3) | (header[5] >> 5)
            end = pos + size
            if size >= 7 and (end == len(payload) or
                              (end + 7 <= len(payload) and payload[end] in (255, 255 ^ key))):
                sizes.append(size)
                if size == previous_size or (split == 7 and previous_size is None):
                    break
        if not sizes:
            break
        size = min(sizes, key=lambda value: abs(value - previous_size)) if previous_size else sizes[0]
        previous_size = size
        if bool(mask) != encrypted:
            (starts if mask else ends).append((previous + 1, pos))
            encrypted = bool(mask)
        previous, pos = pos, pos + size

    if not starts or not ends:
        return None
    # The nth start is n*step; the nth end is n*step+length.
    lower = max((lo + n - 1) // n for n, (lo, hi) in enumerate(starts, 1))
    upper = min(hi // n for n, (lo, hi) in enumerate(starts, 1))
    for step in range(lower, min(MAX_DISCOVERY_STEP, upper) + 1):
        low = max(1, max(lo - n * step for n, (lo, hi) in enumerate(ends)))
        high = min(step, min(hi - n * step for n, (lo, hi) in enumerate(ends)))
        for length in range(low, high + 1):
            if param_sha256(step, length, key) == digest:
                return CryptorParams(step, length, key)
    return None


def discover_bdve_params(data: bytes, key: int, footer: BdveFooter, log: LogFn) -> CryptorParams:
    # The audio sync byte is 0xff. For MP4 the first size byte is usually zero.
    for step, length in BDVE_KNOWN_PROFILES:
        for candidate_key in (key, key ^ 255):
            if param_sha256(step, length, candidate_key) == footer.sha256:
                return CryptorParams(step, length, candidate_key)

    cached = _verified_profiles.get(footer.sha256)
    if cached is not None:
        return cached

    audio_key = key ^ 255
    if footer.start >= 7 and (data[1] ^ audio_key) & 0xF6 == 0xF0:
        audio = data[:footer.start]
        for split_headers in (False, True):
            params = discover_adts_params(audio, audio_key, footer.sha256, split_headers=split_headers)
            if params:
                _verified_profiles[footer.sha256] = params
                return params

    # Padding and sample tables often straddle an XOR boundary. A run of
    # encoded zeroes followed by literal zeroes ends at n * step + length.
    # The opposite transition starts at n * step. Only accept a footer hash match.
    if key:
        zero = bytes(8)
        encoded = bytes([key]) * 8
        starts = re.finditer(re.escape(zero + encoded), data)
        ends = [m.start() + 8 for m in islice(re.finditer(re.escape(encoded + zero), data), 64)]
        for match in islice(starts, 64):
            boundary = match.start() + 8
            for divisor in range(1, math.isqrt(boundary) + 1):
                if boundary % divisor:
                    continue
                for step in (divisor, boundary // divisor):
                    if step > MAX_DISCOVERY_STEP:
                        continue
                    for end in ends:
                        length = end % step
                        if length and param_sha256(step, length, key) == footer.sha256:
                            params = CryptorParams(step, length, key)
                            _verified_profiles[footer.sha256] = params
                            return params

    observations: list[tuple[int, bool]] = [(0, True), (4, True), (32, True)]
    # Compressed media can contain literal box names by chance. Searching the
    # entire payload for those names produces false encryption observations
    # and can exclude the exact profile even when its footer hash is valid.
    # Use sample-table offsets below instead of unvalidated marker matches.

    payload = data[: footer.start]

    # Para archivos de audio (AAC/ADTS u otros sin moov/ftyp)
    if not (b"moov" in payload or b"ftyp" in payload or xor_bytes(b"moov", key) in payload or xor_bytes(b"ftyp", key) in payload):
        raise DecodeError("Perfil de audio desconocido. No se pudo verificar el descifrado.")

    full_xor_payload = xor_bytes(payload, key)
    try:
        samples = parse_video_samples(full_xor_payload)
    except DecodeError:
        samples = parse_video_samples(payload)
    log(f"parsed {len(samples):,} video samples for parameter discovery")

    for sample in samples:
        if sample.pos < 0 or sample.size <= 0 or sample.pos + sample.size > footer.start:
            continue

        raw_chunk = data[sample.pos : sample.pos + min(sample.size, 64)]
        xor_chunk = xor_bytes(raw_chunk, key)
        raw_score = score_h264_sample(raw_chunk)
        xor_score = score_h264_sample(xor_chunk)
        if xor_score != raw_score:
            observations.append((sample.pos, xor_score > raw_score))

    target = footer.sha256
    ordered = sorted(set(observations))
    wraps = [(a[0], b[0]) for a, b in zip(ordered, ordered[1:]) if not a[1] and b[1]]
    if not any(not encrypted for _, encrypted in ordered):
        raise DecodeError("No hay muestras sin cifrar para identificar el perfil BDVE.")
    if wraps:
        first_plain, first_encrypted = wraps[0]
        upper = min(MAX_DISCOVERY_STEP, first_encrypted)
        split = min(first_plain, upper)
        ranges = (range(split + 1, upper + 1), range(1, split + 1))
    else:
        ranges = (range(1, MAX_DISCOVERY_STEP + 1),)
    first_wraps = wraps[:3]
    key_byte = bytes([key])
    attempts = 0
    for step in chain.from_iterable(ranges):
        if step % 100000 == 0:
            log(f"Buscando el perfil BDVE: paso {step:,}")
        if any(a // step == b // step for a, b in first_wraps):
            continue
        low = 1
        high = step
        for pos, encrypted in observations:
            remainder = pos % step
            if encrypted:
                low = max(low, remainder + 1)
            else:
                high = min(high, remainder)
            if low > high:
                break

        if low > high:
            continue

        step_bytes = step.to_bytes(4, "big")
        for length in range(low, high + 1):
            attempts += 1
            if attempts % 1000000 == 0:
                log(f"Verificando el perfil BDVE: {attempts:,} combinaciones")
            if hashlib.sha256(step_bytes + length.to_bytes(4, "big") + key_byte).digest() == target:
                params = CryptorParams(step, length, key)
                _verified_profiles[target] = params
                return params

    raise DecodeError("Could not derive BDVE cryptor parameters from this file.")


def _parameters(data, logger):
    key = data[0]
    footer = parse_bdve_footer(data)
    if footer is None:
        raise DecodeError("No BDVE cryptor footer was found.")
    if footer.start <= 0:
        raise DecodeError("El archivo no contiene datos de audio o video.")
    if footer.cryptor_type != 1:
        raise DecodeError(f"Unsupported BDVE cryptor type: {footer.cryptor_type}")

    logger("Identificando el perfil de cifrado…")
    params = discover_bdve_params(data, key, footer, logger)
    logger(
        "BDVE exact decrypt: "
        f"step={params.step:,}, length={params.length:,}, "
        f"key=0x{params.key:02X}, footer={footer.size} bytes"
    )

    return footer, params


def decode_bytes(data: bytes, log: LogFn | None = None) -> tuple[bytes, CryptorParams]:
    logger = log or (lambda message: None)
    if not data:
        raise DecodeError("Input file is empty.")

    footer, params = _parameters(data, logger)

    result = bytearray(data[: footer.start])
    xor_table = bytes(b ^ params.key for b in range(256))
    for block_start in range(0, len(result), params.step):
        block_end = min(block_start + params.length, len(result))
        chunk = result[block_start:block_end]
        result[block_start:block_end] = chunk.translate(xor_table)

    return bytes(result), params


def decode_file(input_path: Path, output_path: Path, log: LogFn | None = None,
                progress: Callable[[int], None] | None = None) -> CryptorParams:
    logger = log or (lambda message: None)
    if input_path.resolve() == output_path.resolve():
        raise DecodeError("Output path must be different from input path.")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with input_path.open("rb") as source:
        if not os.fstat(source.fileno()).st_size:
            raise DecodeError("Input file is empty.")
        with mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as data:
            footer, params = _parameters(data, logger)
            table = bytes(value ^ params.key for value in range(256))
            with tempfile.NamedTemporaryFile(dir=output_path.parent, suffix=".decrypt.tmp", delete=False) as handle:
                temp = Path(handle.name)
            try:
                with temp.open("wb") as output:
                    # Each chunk contains whole periods, so its XOR phase starts at zero.
                    chunk_size = params.step * max(1, (4 * 1024 * 1024) // params.step)
                    for start in range(0, footer.start, chunk_size):
                        end = min(start + chunk_size, footer.start)
                        block = bytearray(data[start:end])
                        for offset in range(0, len(block), params.step):
                            span = slice(offset, offset + params.length)
                            block[span] = block[span].translate(table)
                        output.write(block)
                        if progress:
                            progress(end * 100 // footer.start)
                os.replace(temp, output_path)
            finally:
                temp.unlink(missing_ok=True)
    return params
