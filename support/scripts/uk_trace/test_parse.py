# SPDX-License-Identifier: BSD-3-Clause */

from dataclasses import dataclass

import pytest

import uk_trace.parse as parser


def makedef(cookie: int, name: str, fmt: str, sizes: list[int], types: list[int]) -> bytes:
    assert len(sizes) == len(types)
    total_def_size = 21 + len(sizes) + len(types) + len(name) + len(fmt)
    return (
        b"TPde"
        + total_def_size.to_bytes(length=4, byteorder="little")
        + cookie.to_bytes(length=8, byteorder="little")
        + bytes([len(sizes), 1 + len(name), 1 + len(fmt)])
        + bytes(sizes)
        + bytes(types)
        + name.encode() + b"\x00"
        + fmt.encode() + b"\x00"
    )


def test_makedef():
    res = makedef(
        cookie=0x212065696b6f6f63,
        name="tracepoint",
        fmt="%*d - %s",
        sizes=[4, 4, 8],
        types=[0, 0, 1],
    )
    assert res == (
        # Magic
        b"TPde"
        # Record size
        b"\x2d\x00\x00\x00"
        # Cookie (0x212065696b6f6f63 little endian)
        b"cookie !"
        # Number of args
        b"\x03"
        # Name len
        b"\x0b"
        # Fmt len
        b"\x09"
        # Arg sizes [4, 4, 8]
        b"\x04\x04\x08"
        # Arg types [int, int, str]
        b"\x00\x00\x01"
        # Name
        b"tracepoint\x00"
        # Fmt
        b"%*d - %s\x00"
    )


@dataclass
class TpDefTestcase:
    c_fmt: str
    py_fmt: str
    sizes: list[int]
    types: list[int]
    signed: list[bool]
    fmt_args: list[int | str]
    formatted: str
    ptr_size: int = 8


TP_DEF_TESTCASES = [
    # Base case
    TpDefTestcase("%d", "%d", [4], [0], [True], [3], "3"),
    TpDefTestcase("%d", "%d", [4], [0], [True], [-3], "-3"),
    # Char (including non-ASCII)
    TpDefTestcase("%c", "%c", [4], [0], [False], [42], "*"),
    TpDefTestcase("%c", "%c", [4], [0], [False], [233], "é"),
    # String
    TpDefTestcase("%s", "%s", [8], [1], [False], ["hello"], "hello"),
    # Different int lengths
    TpDefTestcase("%hhd %hd %d %ld %lld", "%d %d %d %d %d", [1, 2, 4, 4, 8], [0] * 5 , [True] * 5, [3]*5, "3 3 3 3 3"),
    TpDefTestcase("%hhd %hd %d %ld %lld", "%d %d %d %d %d", [1, 2, 4, 4, 8], [0] * 5 , [True] * 5, [-3]*5, "-3 -3 -3 -3 -3"),
    # Different unsigned int lengths
    TpDefTestcase("%hhu %hu %u %lu %llu", "%u %u %u %u %u", [1, 2, 4, 4, 8], [0] * 5 , [False] * 5, [3]*5, "3 3 3 3 3"),
    # Strip thousands separator
    TpDefTestcase("%'d", "%d", [4], [0], [True], [12345], "12345"),
    # Take an additional arg for integer format width
    TpDefTestcase("%*d", "%*d", [4, 4], [0, 0], [False, True], [3, 4], "  4"),
    # Pointer size on 64b machine
    TpDefTestcase("%p", "0x%016x", [8], [0], [False], [3], "0x0000000000000003"),
    # Pointer size on 32b machine
    TpDefTestcase("%p", "0x%08x", [4], [0], [False], [3], "0x00000003", ptr_size=4),
    # Precision format is kept in python
    TpDefTestcase("%.3d", "%.3d", [4], [0], [True], [3], "003"),
    # Take an additional arg for precision format width
    TpDefTestcase("%.*d", "%.*d", [4, 4], [0, 0], [False, True], [3, 4], "004"),
    # Take 2 additional args for width+precision format
    TpDefTestcase("%*.*d", "%*.*d", [4, 4, 4], [0, 0, 0], [False, False, True], [3, 4, 5], "0005"),
    # Pointer variants
    TpDefTestcase(
        "#%p#%6p#%-6p#%*p#%-*p#",
        "#0x%08x#%6x#%-6x#%*x#%-*x#",
        [4, 4, 4, 4, 4, 4, 4],
        [0, 0, 0, 0, 0, 0, 0],
        [False, False, False, False, False, False, False],
        [0xcafe, 0xcafe, 0xcafe, 8, 0xcafe, 8, 0xcafe],
        "#0x0000cafe#  cafe#cafe  #    cafe#cafe    #",
        ptr_size=4,
    ),
]

@pytest.mark.parametrize("tc", TP_DEF_TESTCASES)
def test_get_tp_definitions(caplog, tc):
    res = parser.get_tp_definitions(
        makedef(42, "tracepoint", tc.c_fmt, tc.sizes, tc.types),
        ptr_size=tc.ptr_size,
    )
    assert res == {
        42: parser.tp_definition(
            name="tracepoint",
            fmt=tc.py_fmt,
            args_nr=len(tc.sizes),
            sizes=tc.sizes,
            types=tc.types,
            signed=tc.signed,
        )
    }

    sample = parser.tp_sample(tp=res[42], time=0, args=tc.fmt_args)
    assert sample.formatted_args == tc.formatted

    assert not caplog.records, "No warning log should have been emitted"


@pytest.mark.parametrize("ptr_size", [4, 8])
def test_get_multiple_definitions(ptr_size):
    """
    Parse all definitions packed together in the same buffer. This should
    give the same results as parsing them individually
    """
    testcases = [tc for tc in TP_DEF_TESTCASES if tc.ptr_size == ptr_size]
    definitions = b"".join(
        makedef(i, "tracepoint", tc.c_fmt, tc.sizes, tc.types)
        for i, tc in enumerate(testcases)
    )
    res = parser.get_tp_definitions(definitions, ptr_size)
    assert res == {
        i: parser.tp_definition(
            name="tracepoint",
            fmt=tc.py_fmt,
            args_nr=len(tc.sizes),
            sizes=tc.sizes,
            types=tc.types,
            signed=tc.signed,
        ) for i, tc in enumerate(testcases)
    }


def test_tp_parse_sample():
    tp_def = parser.tp_definition(
        name="tracepoint",
        fmt="%-*x",
        args_nr=1,
        sizes=[4, 4],
        types=[0, 0],
        signed=[False, True],
    )
    sample = tp_def.parse_sample(
        time=0,
        data=parser.unpacker(b"\x0a\x00\x00\x00\x78\x56\x34\x12"),
    )
    assert sample.args == [10, 0x12345678]
    assert str(sample.formatted_args) == "12345678  "


def test_tp_parse_sample_data_too_short():
    tp_def = parser.tp_definition(
        name="tracepoint",
        fmt="%-*x",
        args_nr=1,
        sizes=[4, 4],
        types=[0, 0],
        signed=[False, True],
    )

    with pytest.raises(parser.EndOfBuffer):
        tp_def.parse_sample(
            time=0,
            data=parser.unpacker(b"\x0a\x00\x00\x00\x78\x56\x34"),
        )


def test_sample_parser():
    keyvals = {"format_version": 1}
    def_buf = makedef(
        cookie=0xaaaaaaaaaaaaaaaa,
        name="A-tracepoint",
        fmt="%*d - %s",
        sizes=[4, 4, 8],
        types=[0, 0, 1],
    ) + makedef(
        cookie=0xbbbbbbbbbbbbbbbb,
        name="B-tracepoint",
        fmt="%p",
        sizes=[8],
        types=[0],
    )
    trace_buf = (
        # Sample A
        b"TRhd\x13\x00\x00\x00"
        b"\x01\x00\x00\x00\x00\x00\x00\x00"
        b"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        b"\x03\x00\x00\x00\x2a\x00\x00\x00\x06Hello!"
        # Sample B
        b"TRhd\x08\x00\x00\x00"
        b"\x19\x00\x00\x00\x00\x00\x00\x00"
        b"\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb"
        b"\xef\xcd\xab\x89\x67\x45\x23\x01"
        # Sample A with empty string
        b"TRhd\xd0\x00\x00\x00"
        b"\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        b"\x03\x00\x00\x00\x2a\x00\x00\x00\x00"
    )

    res = [
        x.tabulate_fmt()
        for x in parser.sample_parser(keyvals, def_buf, trace_buf, 8)
    ]

    assert res == [
        [1, "A-tracepoint", " 42 - Hello!"],
        [25, "B-tracepoint", "0x0123456789abcdef"],
        [256, "A-tracepoint", " 42 - "],
    ]


def test_sample_parser_incomplete_sample():
    keyvals = {"format_version": 1}
    def_buf = makedef(0xa, "A-tracepoint", "%d%d", sizes=[4, 4], types=[0, 0])
    trace_buf = (
        # Sample header is correct
        b"TRhd\x08\x00\x00\x00"
        b"\x01\x00\x00\x00\x00\x00\x00\x00"
        b"\x0a\x00\x00\x00\x00\x00\x00\x00"
        # But there are only 4B, while 2x4B are expected in the definition
        b"\x03\x00\x00\x00"
    )

    res = [*parser.sample_parser(keyvals, def_buf, trace_buf, 8)]
    assert res == []


def test_sample_parser_missing_magic():
    keyvals = {"format_version": 1}
    def_buf = makedef(0xa, "A-tracepoint", "%d", sizes=[4], types=[0])
    trace_buf = (
        # No leading magic to find
        b"No record here, but here's a song: lalalala"
    )

    res = [*parser.sample_parser(keyvals, def_buf, trace_buf, 8)]
    assert res == []


def test_sample_parser_missing_definition():
    keyvals = {"format_version": 1}
    def_buf = makedef(0xa, "A-tracepoint", "%d", sizes=[4], types=[0])
    trace_buf = (
        # === First sample: erroneous ===
        b"TRhd\x04\x00\x00\x00"
        b"\x01\x00\x00\x00\x00\x00\x00\x00"
        b"cookie !" # This cookie has no definition !
        b"\x03\x00\x00\x00"
        # === Second sample: valid ("42")
        b"TRhd\x04\x00\x00\x00"
        b"\x01\x00\x00\x00\x00\x00\x00\x00"
        b"\x0a\x00\x00\x00\x00\x00\x00\x00"
        b"\x2a\x00\x00\x00"
    )

    res = [
        x.tabulate_fmt()
        for x in parser.sample_parser(keyvals, def_buf, trace_buf, 8)
    ]
    assert res == [
        # Only the second sample is present
        [1, "A-tracepoint", "42"],
    ]
