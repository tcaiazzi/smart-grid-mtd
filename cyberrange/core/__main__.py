"""python -m cyberrange.core <command>

    scenarios                    list the registered scenarios
    export <scenario> --out DIR  write the scenario's default topology as a
                                 Kathará lab dir (lab.conf + .startup files)
    loc [--markdown FILE]        platform vs scenario code size
"""

import argparse
import json
import sys

from cyberrange.core import registry


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python -m cyberrange.core",
                                 description="Platform utilities")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("scenarios", help="list the registered scenarios")
    ex = sub.add_parser("export", help="topology -> Kathará lab dir")
    ex.add_argument("scenario", choices=registry.names())
    ex.add_argument("--out", required=True)
    ex.add_argument("--copy-files", action="store_true",
                    help="copy the guest files into the lab dir instead of listing them")
    lc = sub.add_parser("loc", help="platform vs scenario code size")
    lc.add_argument("--markdown", default=None, help="also write the table here")
    lc.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    if args.cmd == "scenarios":
        for name in registry.names():
            s = registry.get(name)
            print(f"{name:<10} lab={s.lab_name:<6} {type(s).__module__}")
    elif args.cmd == "export":
        from cyberrange.core.cli import default_args
        from cyberrange.core.topology import export_lab_conf
        s = registry.get(args.scenario)
        path = export_lab_conf(s.topology(default_args(s)), args.out, copy_files=args.copy_files)
        print(path)
    elif args.cmd == "loc":
        from cyberrange.core import loc
        r = loc.report()
        md = loc.format_markdown(r)
        if args.json:
            json.dump({k: v for k, v in r.items() if k != "files"}, sys.stdout, indent=2)
            print()
        else:
            print(md)
        if args.markdown:
            with open(args.markdown, "w") as f:
                f.write(md)


if __name__ == "__main__":
    main()
