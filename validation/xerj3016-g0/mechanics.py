"""Disabled G0 authoring: synthetic public-API fusion mechanics, not quality."""
from __future__ import annotations

from copy import deepcopy
from fractions import Fraction
import hashlib
import json
import math
import os
from pathlib import Path


DOCS = (
    ("d1", "Reset your password", [1.00, 0.15, 0.0, 0.10]),
    ("d2", "Regain entry to a locked-out account", [0.95, 0.10, 0.0, 0.15]),
    ("d3", "Password complexity and rotation policy", [0.15, 1.00, 0.0, 0.10]),
    ("d4", "How to bake sourdough bread", [0.00, 0.00, 1.0, 0.10]),
    ("d5", "Change your account password", [0.85, 0.25, 0.0, 0.20]),
)
LEG0 = {"match": {"title": "reset password"}}
LEG1 = {"knn": {"field": "vec", "query_vector": [1.0, 0.20, 0.0, 0.10], "k": 3}}
EXAMPLE = "docs/examples/hybrid-search/hybrid_search.py"
EXAMPLE_BYTES = 5958
EXAMPLE_GIT_OID = "afdfe6c5d15f4607f051af94aad5bd192fa25fc8"
REL_TOL = 2e-6
ABS_TOL = 2e-7


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _save(out, name, value):
    # The callback returns parsed JSON; these retain its unmodified JSON values,
    # not a claim of HTTP-wire byte identity. Only fixed synthetic requests run.
    (out / name).write_text(json.dumps(value, indent=2) + "\n")


def _hits(response, label, *, unique_scores=False):
    _require(isinstance(response, dict), label + ": not an object")
    _require(response.get("timed_out") is False, label + ": missing/true timed_out")
    shards = response.get("_shards")
    if shards is not None:
        _require(shards.get("failed") == 0, label + ": failed shards")
    block = response["hits"]
    hits = block["hits"]
    _require(isinstance(hits, list) and hits, label + ": empty/malformed hit list")
    ids = [h["_id"] for h in hits]
    _require(all(isinstance(x, str) and x for x in ids), label + ": invalid IDs")
    _require(len(set(ids)) == len(ids), label + ": duplicate hit ID")
    scores = [h["_score"] for h in hits]
    _require(all(type(x) in (int, float) and math.isfinite(x) for x in scores),
             label + ": nonfinite/nonnumeric score")
    _require(scores == sorted(scores, reverse=True), label + ": scores not descending")
    if unique_scores:
        _require(len(set(scores)) == len(scores), label + ": kNN score ties")
    total = block["total"]
    _require(isinstance(total, dict) and total.get("relation") == "eq"
             and type(total.get("value")) is int and total["value"] == len(hits),
             label + ": incomplete/bounded hit pool")
    return hits


def oracle(legs, weights, k):
    """Independent exact rational sum using one-based ranks, absent leg = 0."""
    _require(type(k) is int and k >= 1, "RRF smoothing k must be a positive integer")
    _require(len(legs) == len(weights) and len(legs) > 0, "leg/weight cardinality")
    result = {}
    for leg, weight in zip(legs, weights):
        _require(type(weight) in (int, float) and math.isfinite(weight) and weight >= 0,
                 "weight must be finite and nonnegative")
        ids = [h["_id"] for h in leg]
        _require(len(ids) == len(set(ids)), "duplicate ID inside oracle leg")
        w = Fraction(str(weight))
        for rank, doc_id in enumerate(ids, 1):
            result[doc_id] = result.get(doc_id, Fraction(0)) + w / (k + rank)
    return result


def _check_fused(response, expected, label):
    hits = _hits(response, label)
    ids = [h["_id"] for h in hits]
    scores = {h["_id"]: h["_score"] for h in hits}
    _require(set(ids) == set(expected), label + ": wrong complete union IDs")
    for doc_id, exact in expected.items():
        _require(math.isclose(scores[doc_id], float(exact), rel_tol=REL_TOL, abs_tol=ABS_TOL),
                 label + ": wrong one-based weighted RRF score for " + doc_id)
    positions = {doc_id: i for i, doc_id in enumerate(ids)}
    # Never assert a tie-break. Only exact expected scores distinguishable at
    # the float32 comparison tolerance must preserve strict ordering.
    for a, score_a in expected.items():
        for b, score_b in expected.items():
            margin = 2 * max(ABS_TOL, REL_TOL * max(abs(float(score_a)), abs(float(score_b))))
            if float(score_a - score_b) > margin:
                _require(positions[a] < positions[b], label + ": reversed strict score order")
    return {"actual": scores, "actualOrder": ids,
            "expected": {doc_id: float(value) for doc_id, value in expected.items()},
            "exactExpectedFractions": {doc_id: str(value) for doc_id, value in expected.items()}}


def _fixture_response(scores, order=None):
    order = list(order) if order is not None else sorted(scores, key=lambda x: -scores[x])
    return {"timed_out": False, "_shards": {"failed": 0},
            "hits": {"total": {"value": len(order), "relation": "eq"},
                     "hits": [{"_id": key, "_score": float(scores[key])} for key in order]}}


def fixture():
    """Run the real oracle/readers on hand-calculated success and mutations."""
    legs = [[{"_id": "a"}, {"_id": "b"}], [{"_id": "b"}, {"_id": "c"}]]
    # Hand derivation independent of oracle(): a=2/8, b=2/9+(1/2)/8, c=(1/2)/9.
    exact = {"a": Fraction(1, 4), "b": Fraction(41, 144), "c": Fraction(1, 18)}
    _require(oracle(legs, [2.0, 0.5], 7) == exact, "hand-derived rational positive")
    positive = _fixture_response(exact)
    _check_fused(positive, exact, "fixture-positive")
    mutations = {
        "zero-based-rank": _fixture_response({"a": 2 / 7, "b": 2 / 8 + 0.5 / 7, "c": 0.5 / 8}),
        "ignored-weights": _fixture_response({"a": 1 / 8, "b": 1 / 9 + 1 / 8, "c": 1 / 9}),
        "ignored-custom-k": _fixture_response({"a": 2 / 61, "b": 2 / 62 + 0.5 / 61, "c": 0.5 / 62}),
        "invented-missing-leg-contribution": _fixture_response(dict(exact, a=exact["a"] + Fraction(1, 20))),
        "dropped-missing-leg-document": _fixture_response({"a": exact["a"], "b": exact["b"]}),
        "reversed-strict-order": _fixture_response(exact, ["c", "a", "b"]),
    }
    duplicate = deepcopy(positive)
    duplicate["hits"]["hits"].append(deepcopy(duplicate["hits"]["hits"][0]))
    duplicate["hits"]["total"]["value"] += 1
    mutations["duplicate-hit"] = duplicate
    nonfinite = deepcopy(positive)
    nonfinite["hits"]["hits"][0]["_score"] = float("nan")
    mutations["nonfinite-score"] = nonfinite
    rejected = []
    for name, response in mutations.items():
        try:
            _check_fused(response, exact, "fixture-" + name)
        except ValueError:
            rejected.append(name)
        else:
            raise ValueError("mutation accepted: " + name)
    tied = _fixture_response({"a": 0.5, "b": 0.5}, ["b", "a"])
    _require([h["_id"] for h in _hits(tied, "BM25-ties")] == ["b", "a"],
             "BM25 returned tied ranks must be retained")
    try:
        _hits(tied, "knn-ties", unique_scores=True)
    except ValueError:
        rejected.append("knn-tie")
    else:
        raise ValueError("kNN tie accepted")
    return {"state": "PASS", "handCalculatedPositive": True, "negativeControls": rejected,
            "BM25TieRanksAcceptedAsReturned": True, "missingLegAbsentContributionExactlyZero": True,
            "scope": "actual helper functions on synthetic JSON; no node/project execution"}


def run(repo: Path, out: Path, run_command, request) -> dict:
    repo, out = Path(repo), Path(out)
    _require(os.environ.get("XERJ_DISABLE_FEEDBACK") == "true", "node feedback-disable environment missing")
    out.mkdir(parents=True, exist_ok=True)
    progress = {"state": "RUNNING", "cases": [], "syntheticMechanicsNotQualityBenchmark": True}
    _save(out, "mechanics.json", progress)
    example = repo / EXAMPLE
    _require(example.is_file() and not example.is_symlink(), "original example missing/symlink")
    source = example.read_bytes()
    _require(len(source) == EXAMPLE_BYTES
             and hashlib.sha1(b"blob " + str(len(source)).encode() + b"\0" + source).hexdigest() == EXAMPLE_GIT_OID,
             "original example source identity changed")
    # The unmodified example permits URL environment overrides; pin both to
    # this owned loopback endpoint for its bounded child, then restore them.
    prior = {key: os.environ.get(key) for key in ("XERJ_URL", "BASE")}
    try:
        os.environ["XERJ_URL"] = os.environ["BASE"] = "http://127.0.0.1:9200"
        receipt = run_command("original-five-doc-example", ["python3", EXAMPLE],
                              cwd=repo, seconds=120, check=True)
        _require(receipt.get("exit") == 0 and receipt.get("complete") is True,
                 "original example did not complete successfully")
    finally:
        for key, value in prior.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def call(name, body):
        _save(out, name + "-request.json", {"method": "POST", "path": "/helpdesk/_search", "body": body})
        try:
            result = request("POST", "/helpdesk/_search", body)
        except Exception as exc:
            _save(out, name + "-failure.json", {"state": "FAILED", "errorType": type(exc).__name__})
            raise
        _save(out, name + "-raw.json", result)
        return result

    corpus = _hits(call("corpus", {"size": 50, "from": 0, "query": {"match_all": {}}}), "corpus")
    expected_docs = {key: {"title": title, "vec": vec} for key, title, vec in DOCS}
    _require({h["_id"] for h in corpus} == set(expected_docs), "not exactly original five documents")
    for hit in corpus:
        _require(hit["_source"] == expected_docs[hit["_id"]], "original synthetic source changed")
    # run_hybrid_with_deadline uses max(50,size+from) and from=0 for EACH
    # leg. Mirror that request, not a guessed leg page size. Top-level kNN
    # still caps its pool at k=3 before windowing (knn_result_from_ranked).
    legs = []
    for i, query in enumerate((LEG0, LEG1)):
        raw = call("leg-" + str(i), {"size": 50, "from": 0, "query": deepcopy(query)})
        legs.append(_hits(raw, "leg-" + str(i), unique_scores=(i == 1)))
    _require(len(legs[1]) == 3, "top-level kNN pool does not equal requested k=3")
    lexical, vector = ({h["_id"] for h in leg} for leg in legs)
    _require("d2" in vector - lexical and "d3" in lexical - vector, "missing-leg fixture not established")
    _require((lexical | vector) <= set(expected_docs), "leg contains nonsynthetic document")
    ties = {}
    for hit in legs[0]:
        ties.setdefault(str(hit["_score"]), []).append(hit["_id"])
    progress.update(originalExampleGitOID=EXAMPLE_GIT_OID, originalExampleReceipt=receipt,
                    allFiveDocumentIDs=sorted(expected_docs), oracleLegRequestSize=50,
                    knnQueryK=3, knnUniqueFiniteScores=True,
                    BM25TiedGroups=[ids for ids in ties.values() if len(ids) > 1],
                    missingKeywordLeg=sorted(vector - lexical), missingVectorLeg=sorted(lexical - vector))
    cases = (("default", [1.0, 1.0], 60, "rrf"),
             ("unequal", [2.0, 0.5], 60, "rrf"),
             ("custom-k", [2.0, 0.5], 7, {"type": "rrf", "k": 7}),
             ("zero-keyword", [0.0, 1.0], 7, {"type": "rrf", "k": 7}))
    for name, weights, k, fusion in cases:
        body = {"size": 5, "from": 0, "query": {"hybrid": {
            "queries": [{"query": deepcopy(q), "weight": w} for q, w in zip((LEG0, LEG1), weights)],
            "fusion": fusion}}}
        actual = call("hybrid-" + name, body)
        expected = oracle(legs, weights, k)
        checked = _check_fused(actual, expected, name)
        for doc_id in vector - lexical:
            rank = next(i for i, hit in enumerate(legs[1], 1) if hit["_id"] == doc_id)
            _require(expected[doc_id] == Fraction(str(weights[1])) / (k + rank), "missing lexical leg not zero")
        for doc_id in lexical - vector:
            rank = next(i for i, hit in enumerate(legs[0], 1) if hit["_id"] == doc_id)
            _require(expected[doc_id] == Fraction(str(weights[0])) / (k + rank), "missing vector leg not zero")
        progress["cases"].append(dict(case=name, weights=weights, k=k, **checked))
        _save(out, "mechanics.json", progress)
    progress.update(state="PASS", independentFormula="sum(weight/(k+oneBasedRank)); absent leg contributes zero",
                    noDefaultOrRetrievalQualityClaim=True,
                    responseEvidence="callback JSON objects preserved; not HTTP-wire byte identity",
                    fusedTiePolicy="strict distinguishable expected scores only; no tie-break assertion")
    _save(out, "mechanics.json", progress)
    return progress
