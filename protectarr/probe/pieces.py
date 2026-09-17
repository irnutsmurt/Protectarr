"""Which pieces must be verified before a byte range of a file can be read.

The probe used to ask one question - "is this file's *first* piece verified?" -
and then read as many bytes as the header budget asked for. Those are not the
same question. A file in a multi-file torrent begins wherever the previous file
ended, which is very rarely a piece boundary, so a 4 KiB header read from a file
that starts 200 bytes before the end of its first piece needs two pieces, not
one. The second piece may be nowhere near downloaded.

Reading past the verified span does not fail. The bytes beyond it are whatever
the filesystem has, which for a sparse file is zeros, and a header that is half
real and half padding is exactly the input a structural parser must never see.

Everything here is derived from what qBittorrent already reports - each file's
`piece_range` and `size`, and the torrent's `piece_size`. There is deliberately
no second source of availability: the piece states are authoritative and this
module only works out which of them to consult.

The offset of a file inside its first piece is not reported directly, so it is
derived by summing the sizes of the files before it - and then *checked* against
the `piece_range` qBittorrent reported for that same file. If the two disagree,
the derivation is wrong (a hidden padding file, a reordered list) and the answer
degrades to the worst case rather than to a guess: assume the file begins at the
last byte of its first piece, which can only ever require more pieces than the
truth, never fewer.
"""

VERIFIED = 2        # qBittorrent piece state: hash checked and on disk


def _int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def piece_range(file_entry):
    """`(first, last)` for one file, or `(None, None)` if it is unusable."""
    pr = (file_entry or {}).get("piece_range")
    if not isinstance(pr, (list, tuple)) or len(pr) < 2:
        return None, None
    first, last = _int(pr[0]), _int(pr[1])
    if first is None or last is None or first < 0 or last < first:
        return None, None
    return first, last


def _offset_in_first_piece(files, index, first, last, piece_size, size):
    """Where this file starts inside its first piece, or None if unprovable.

    The sum is only trusted when it reproduces the `piece_range` qBittorrent
    independently reported for this file. That check is what makes a hidden
    padding file or a reordered list a fallback rather than a wrong answer.
    """
    if size is None or size <= 0:
        return None
    offset = 0
    for f in files[:index]:
        prev = _int((f or {}).get("size"))
        if prev is None or prev < 0:
            return None
        offset += prev
    if offset // piece_size != first:
        return None
    if (offset + size - 1) // piece_size != last:
        return None
    return offset % piece_size


def covering(files, index, span, piece_size):
    """Piece indices covering the first `span` bytes of `files[index]`.

    Returns None when coverage cannot be established at all. A caller must read
    None as "not available" and never as "available" - that is the whole point
    of the module.
    """
    if not files or not 0 <= index < len(files):
        return None
    piece_size = _int(piece_size)
    span = _int(span)
    if not piece_size or piece_size <= 0 or not span or span <= 0:
        return None

    entry = files[index]
    first, last = piece_range(entry)
    if first is None:
        return None

    size = _int(entry.get("size"))
    if size is not None and size <= 0:
        return None             # an empty file has no header to classify

    # The span is deliberately *not* clamped to the file size here. It would be
    # redundant: the range is clamped to `last` below, and a file never extends
    # past its own last piece, so asking for more bytes than the file holds can
    # never widen the answer. A clamp that cannot change an answer is a line no
    # test can hold, so it is not written.

    if first == last:
        # The whole file lives inside one piece, so no offset arithmetic is
        # needed and none of it can go wrong. Exact, not a shortcut.
        return [first]

    start = _offset_in_first_piece(files, index, first, last, piece_size, size)
    if start is None:
        # Worst case: the file begins at the final byte of its first piece.
        # Over-requiring a piece costs a retry; under-requiring one costs a
        # verdict read from padding.
        start = piece_size - 1

    end = first + (start + span - 1) // piece_size
    # A file never extends past its own last piece, so this clamp is a fact
    # rather than a concession - it matters when `size` was unreadable and the
    # span above was therefore not clamped to it.
    return list(range(first, min(end, last) + 1))


def verified(piece_states, needed):
    """True only when every needed piece is hash-verified.

    Unknown coverage, a short piece-state array and an out-of-range index all
    answer False. None of them is evidence that the bytes are there.
    """
    if not needed:
        return False
    states = piece_states or ()
    for p in needed:
        if not 0 <= p < len(states) or states[p] != VERIFIED:
            return False
    return True


def scheduled(piece_states, needed):
    """Has qBittorrent asked for any of these pieces yet?

    Non-zero latches in qBittorrent's reporting, so a piece requested, dropped
    and re-requested still reads as scheduled. Any one of the needed pieces
    counts: work has started on the range.
    """
    if not needed:
        return False
    states = piece_states or ()
    return any(0 <= p < len(states) and states[p] for p in needed)
