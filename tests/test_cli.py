from sentinelgate.cli import build_parser


def test_parses_c2_analyse_command() -> None:
    parser = build_parser()

    args = parser.parse_args(
        [
            "c2",
            "analyse",
            "--file",
            "observations.jsonl",
        ]
    )

    assert args.command == "c2"
    assert args.c2_command == "analyse"
    assert args.file == "observations.jsonl"
