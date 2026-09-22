#!/usr/bin/env python3
"""SARIF 출력이 공식 스키마에 맞는지 본다.

사용법: validate_sarif.py <스키마.json> <출력.sarif> [출력.sarif ...]

대조군을 함께 돌린다 — 일부러 깨뜨린 문서가 반드시 실패해야
"통과했다"와 "검증기가 아무것도 안 봤다"가 구별된다.
"""
import copy
import json
import sys

from jsonschema import Draft4Validator  # OASIS 스키마는 draft-04 다


def check(validator, doc, name, want_ok):
    errs = sorted(validator.iter_errors(doc), key=lambda e: list(e.path))
    ok = not errs
    print(f"  {name:32} {'통과' if ok else f'오류 {len(errs)}건'}")
    if ok != want_ok:
        if errs:
            print(f"    {errs[0].message[:300]}")
        else:
            print("    깨뜨렸는데 통과했다 — 검증기가 보고 있지 않다")
        return False
    return True


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2

    schema_path, paths = sys.argv[1], sys.argv[2:]
    validator = Draft4Validator(json.load(open(schema_path, encoding="utf-8")))

    good = True
    docs = []
    for p in paths:
        doc = json.load(open(p, encoding="utf-8"))
        docs.append(doc)
        good &= check(validator, doc, p, True)

    broken = {
        "대조군 - driver.name 제거": lambda d: d["runs"][0]["tool"]["driver"].pop("name"),
        "대조군 - version 변조": lambda d: d.update(version="9.9.9"),
        "대조군 - results 를 객체로": lambda d: d["runs"][0].update(results={}),
    }
    for name, breaker in broken.items():
        d = copy.deepcopy(docs[0])
        breaker(d)
        good &= check(validator, d, name, False)

    return 0 if good else 1


if __name__ == "__main__":
    sys.exit(main())
