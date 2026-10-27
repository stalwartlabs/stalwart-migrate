#!/usr/bin/env python3
"""Convert stalwart-cli declarative plans from the Stalwart v0.16 schema to v1.

  convert_plan.py prepare  plan.ndjson [--answers answers.toml]
  convert_plan.py convert  plan.ndjson -o plan-v1.ndjson [--answers answers.toml] [--report report.txt] [--strict]
  convert_plan.py validate plan-v1.ndjson

The converter is offline. It reads mapping/v016_to_v1.toml, normalize_016x.toml,
prompts.toml and the schema snapshots in mapping/schema (see --mapping-dir), the
same files the Rust migration engine uses.
"""

import argparse
import copy
import gzip
import heapq
import json
import sys
import tomllib
from pathlib import Path

DEFAULT_MAPPING_DIR = Path(__file__).resolve().parent.parent / "mapping"
TYPE_KEY = "@type"
EXPRESSION_SCHEMA = "x:Expression"
EXPRESSION_VARIABLES = "ExpressionVariable"
OBJECT_PREFIX = "x:"
SECRET_MASK = "****"
ANSWERS_VERSION = 1
WRAP = 78
KEEP = "keep"
REMOVE = "remove"
FORWARD = "forward"
REVERSE = "reverse"
WRITE_RANK = ["x:Tenant", "x:Domain", "x:Directory", "x:Role", "x:Account", "x:MailingList"]
ALPHABET = "abcdefghijklmnopqrstuvwxyz792013"
INVERSE = {ch: i for i, ch in enumerate(ALPHABET)}

DROP_NO_EQUIVALENT = "no equivalent in the target version"
DROP_ENTERPRISE = "enterprise only, target is open source"
DROP_NOT_IN_TARGET = "not part of the target schema"
DROP_INVALID = "invalid value"
DROP_OPERATOR = "dropped as answered"
OWNER_REFERENCE = "accountId"
DROP_KEY_LOST = "its unique key is absent or has no equivalent in the target version"
MERGED_OBJECT = "x:EventTracingLevel"
MERGED_PROPERTY = "level"
MERGED_DEFAULT = "info"
VERBOSITY = ["disable", "error", "warn", "info", "debug", "trace"]
KEY_MERGE = "key_merge"
PRINCIPALS_MIGRATED = "migrated"
PRINCIPALS_EXCLUDED = "excluded"
COORDINATOR = "x:Coordinator"
COORDINATOR_DISABLED = "Disabled"
IN_MEMORY_STORE = "x:InMemoryStore"
IN_MEMORY_DEFAULT = "Default"


def drop_orphaned(account):
    return f"its owner {account} is not listed by the source"


def drop_key_conflict(key, kept):
    return f"{kept} has the same unique key {key} in the target version and is kept"


def drop_merged(key, into, original):
    return f"merged into {into}, which has the same unique key {key} in the target version; it was {original}"

UNIQUE_KEYS = {
    "x:Account": ("name", "domainId"),
    "x:AllowedIp": ("address",),
    "x:BlockedIp": ("address",),
    "x:ClusterRole": ("name",),
    "x:Domain": ("name",),
    "x:EventTracingLevel": ("event",),
    "x:HttpLookup": ("namespace",),
    "x:MailingList": ("name", "domainId"),
    "x:MemoryLookupKey": ("namespace", "key"),
    "x:MemoryLookupKeyValue": ("namespace", "key"),
    "x:MtaConnectionStrategy": ("name",),
    "x:MtaDeliverySchedule": ("name",),
    "x:MtaRoute": ("name",),
    "x:MtaTlsStrategy": ("name",),
    "x:MtaVirtualQueue": ("name",),
    "x:NetworkListener": ("name",),
    "x:OAuthClient": ("clientId",),
    "x:SieveSystemScript": ("name",),
    "x:SieveUserScript": ("name",),
    "x:SpamDnsblServer": ("name",),
    "x:SpamFileExtension": ("extension",),
    "x:SpamRule": ("name",),
    "x:SpamTag": ("tag",),
    "x:StoreLookup": ("namespace",),
}

RETIRED_PROMPT_IDS = {"target_store"}

PROMPT_IDS = [
    "blob_store", "edition", "categories", "oidc_directory", "oidc_token_lifetimes", "oauth_registration", "counter_read",
    "http_forwarded", "spam_ai", "ai_model_provider", "dns_sig0", "azure_auth", "in_memory_cluster",
    "enterprise_on_oss", "new_permissions", "changed_defaults",
]


class MappingError(Exception):
    pass


def jmap_id_parse(text):
    if not text or len(text) > 13:
        return None
    value = 0
    for ch in text:
        digit = INVERSE.get(ch)
        if digit is None or value >> 59:
            return None
        value = (value << 5) | digit
    return value


def jmap_id_format(value):
    if value == 0:
        return "a"
    digits = []
    while value:
        digits.append(ALPHABET[value & 31])
        value >>= 5
    return "".join(reversed(digits))


def canonical_object(name):
    return name if name.startswith(OBJECT_PREFIX) else OBJECT_PREFIX + name


class ObjectKey:
    __slots__ = ("object", "kind", "value")

    SINGLETON, ID, CLIENT, LABEL = 0, 1, 2, 3

    def __init__(self, obj, kind=0, value=None):
        self.object = canonical_object(obj)
        self.kind = kind
        self.value = value

    @classmethod
    def parse(cls, text):
        if "/" not in text:
            return cls(text) if text else None
        obj, _, instance = text.partition("/")
        if not obj:
            return None
        if instance.startswith("#"):
            return cls(obj, cls.CLIENT, instance[1:])
        if instance.startswith("="):
            return cls(obj, cls.LABEL, instance[1:])
        value = jmap_id_parse(instance)
        return None if value is None else cls(obj, cls.ID, value)

    def with_object(self, obj):
        return ObjectKey(obj, self.kind, self.value)

    def sort_key(self):
        return (self.kind, self.value if self.value is not None else 0)

    def __str__(self):
        if self.kind == self.SINGLETON:
            return self.object
        if self.kind == self.ID:
            return f"{self.object}/{jmap_id_format(self.value)}"
        if self.kind == self.CLIENT:
            return f"{self.object}/#{self.value}"
        return f"{self.object}/={self.value}"

    def __eq__(self, other):
        return isinstance(other, ObjectKey) and (self.object, self.kind, self.value) == (other.object, other.kind, other.value)

    def __hash__(self):
        return hash((self.object, self.kind, self.value))

    def __repr__(self):
        return f"ObjectKey({self})"


def is_number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def json_equal(a, b):
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if is_number(a) and is_number(b):
        return type(a) is type(b) and a == b
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(json_equal(a[k], b[k]) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(json_equal(x, y) for x, y in zip(a, b))
    return type(a) is type(b) and a == b


def values_equal(a, b):
    if is_number(a) and is_number(b):
        return float(a) == float(b)
    return json_equal(a, b)


SECRET_HINTS = ("secret", "password", "token", "key")
STORE_OBJECTS = ("x:BlobStore", "x:InMemoryStore", "x:SearchStore", "x:DataStore")
MARKER_FALLBACK = ("x:DnsManagement", "x:CertificateManagement", "x:SpamAi")
TENANT_OBJECT = "x:Tenant"
TENANT_REFERENCE = "memberTenantId"
GAP_MISSING = "missing"
GAP_OTHER_TENANT = "other_tenant"


def mask_property(name, ty, value):
    secret = ty.is_secret() if ty is not None else any(h in name.lower() for h in SECRET_HINTS)
    if isinstance(value, (dict, list)):
        return mask_secrets(value)
    if value is None:
        return None
    return SECRET_MASK if secret else value


def mask_all(value):
    if isinstance(value, dict):
        return {k: (v if k == TYPE_KEY else mask_all(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [mask_all(v) for v in value]
    return None if value is None else SECRET_MASK


def mask_secrets(value):
    if isinstance(value, dict):
        return {k: (SECRET_MASK if k == "secret" else mask_secrets(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [mask_secrets(v) for v in value]
    return value


class TypeDef:
    __slots__ = ("kind", "nullable", "name", "format", "min", "max", "min_items", "secret", "cls", "key", "value")

    def __init__(self, raw):
        self.kind = raw["type"]
        self.nullable = bool(raw.get("nullable", False))
        self.name = raw.get("objectName") or raw.get("enumName")
        self.format = raw.get("format")
        self.min = raw.get("min")
        self.max = raw.get("max")
        self.min_items = raw.get("minItems")
        self.secret = self.kind == "string" and self.format in ("secret", "secretText")
        self.cls = TypeDef(raw["class"]) if "class" in raw else None
        self.key = TypeDef(raw["keyClass"]) if "keyClass" in raw else None
        self.value = TypeDef(raw["valueClass"]) if "valueClass" in raw else None

    def is_secret(self):
        return self.secret or (self.kind == "object" and self.name.startswith("x:Secret"))


class Property:
    __slots__ = ("ty", "server_set", "update", "enterprise")

    def __init__(self, raw):
        self.ty = TypeDef(raw["type"])
        self.update = raw.get("update")
        self.server_set = self.update == "serverSet"
        self.enterprise = bool(raw.get("enterprise", False))


class Fields:
    __slots__ = ("properties", "defaults")

    def __init__(self, raw):
        self.properties = {name: Property(p) for name, p in raw.get("properties", {}).items()}
        self.defaults = raw.get("defaults", {})


class SchemaDef:
    __slots__ = ("single", "variants")

    def __init__(self, raw):
        if raw["type"] == "single":
            self.single = raw["schemaName"]
            self.variants = None
        else:
            self.single = None
            self.variants = [(v["name"], v.get("schemaName")) for v in raw["variants"]]

    def variant(self, name):
        for variant in self.variants or ():
            if variant[0] == name:
                return variant
        return None

    def marker_variant(self):
        for variant in self.variants or ():
            if variant[1] is None:
                return variant
        return None


class Schema:
    def __init__(self, raw):
        self.objects = raw["objects"]
        self.schemas = {name: SchemaDef(d) for name, d in raw["schemas"].items()}
        self.fields = {name: Fields(d) for name, d in raw["fields"].items()}
        self.enum_values = {name: [v["name"] for v in values] for name, values in raw["enums"].items()}
        self.enums = {name: set(values) for name, values in self.enum_values.items()}
        self.lower_objects = {}
        for name, obj in self.objects.items():
            if obj.get("type") != "view":
                self.lower_objects.setdefault(name.lower(), name)

    @classmethod
    def load(cls, path):
        with gzip.open(path, "rt", encoding="utf-8") as f:
            return cls(json.load(f))

    def enum_has(self, name, value):
        return value in self.enums.get(name, ())

    def prop(self, fields, name):
        f = self.fields.get(fields)
        return f.properties.get(name) if f else None

    def reference_target(self, name):
        if not name.startswith(OBJECT_PREFIX):
            return None
        obj = self.objects.get(name)
        if obj and obj.get("type") == "view" and obj.get("objectName"):
            return obj["objectName"]
        return name

    def resolve_object(self, name):
        return self.lower_objects.get(canonical_object(name).lower())

    def field_schemas(self, object_name):
        sdef = self.schemas.get(object_name)
        if sdef is None:
            return []
        if sdef.single:
            return [sdef.single]
        return [schema for _, schema in sdef.variants if schema]


class Rule:
    __slots__ = ("kind", "to", "convert", "transform", "variables", "move")

    def __init__(self, kind, to=None, convert="compatible", transform=None, variables=(), move=None):
        self.kind = kind
        self.to = to
        self.convert = convert
        self.transform = transform
        self.variables = tuple(variables)
        self.move = move


def parse_rule(raw, where, file):
    if isinstance(raw, str):
        return Rule("rename", to=raw)
    allowed = {"to", "drop", "convert", "transform", "move", "params", "payload"}
    unknown = set(raw) - allowed
    if unknown:
        raise MappingError(f"{file}: rule {where}: unknown keys {sorted(unknown)}")
    if raw.get("drop"):
        return Rule("drop")
    if raw.get("payload") == "compatible":
        return Rule("payload")
    if "transform" in raw:
        if raw["transform"] not in TRANSFORMS:
            raise MappingError(f"{file}: rule {where}: unknown transform {raw['transform']}")
        return Rule("transform", transform=raw["transform"], variables=raw.get("params", {}).get("variables", ()))
    if "move" in raw:
        obj, _, prop = raw["move"].partition(".")
        return Rule("move", move=(obj, prop))
    if "to" in raw:
        return Rule("rename", to=raw["to"], convert=raw.get("convert", "compatible"))
    if "convert" in raw:
        return Rule("keep", convert=raw["convert"])
    raise MappingError(f"{file}: rule {where}: empty rule")


class Rules:
    def __init__(self, raw, file):
        if raw.get("version") != 1:
            raise MappingError(f"{file}: unsupported version")
        self.objects = {}
        for name, rule in raw.get("objects", {}).items():
            rule = {"to": rule} if isinstance(rule, str) else rule
            self.objects[name] = rule
            if "transform" in rule and rule["transform"] not in TRANSFORMS:
                raise MappingError(f"{file}: unknown transform {rule['transform']}")
        self.variants = {
            union: {name: parse_rule(rule, f"{union}.{name}", file) for name, rule in table.items()}
            for union, table in raw.get("variants", {}).items()
        }
        self.properties = {
            fields: {name: parse_rule(rule, f"{fields}.{name}", file) for name, rule in table.items()}
            for fields, table in raw.get("properties", {}).items()
        }
        self.enums = {}
        for name, table in raw.get("enums", {}).items():
            parsed = {}
            for value, rule in table.items():
                if isinstance(rule, str):
                    parsed[value] = [rule]
                elif rule.get("drop"):
                    parsed[value] = None
                else:
                    target = rule["to"]
                    parsed[value] = [target] if isinstance(target, str) else list(target)
            self.enums[name] = parsed
        self.separators = {name: (sep["from"], sep["to"]) for name, sep in raw.get("enum_separators", {}).items()}
        self.defaults = raw.get("defaults", {})
        self.grants = [(new, old) for new, old in raw.get("permission_grants", {}).items()]
        spam_tags = raw.get("spam_tags", {})
        self.spam_tag_renames = dict(spam_tags.get("renamed", {}))
        self.spam_tag_removed_prefixes = tuple(spam_tags.get("removed_prefixes", []))
        self.spam_tags_added = dict(spam_tags.get("added", {}))
        self.functions = {}
        for name, rule in raw.get("expression_functions", {}).items():
            if isinstance(rule, str):
                self.functions[name] = (rule, [], None)
            else:
                self.functions[name] = (rule["to"], list(rule.get("append_args", [])), rule.get("prompt"))

    def variant(self, union, name):
        return self.variants.get(union, {}).get(name)

    def enum_rule(self, name, value):
        table = self.enums.get(name)
        if table is None or value not in table:
            return False, None
        return True, table[value]

    def default_policy(self, fields, prop):
        table = self.defaults.get(fields)
        if table is None:
            return None
        return table.get(prop, table.get("*"))


class Catalogue:
    def __init__(self, raw):
        if raw.get("version") != 1:
            raise MappingError("prompts.toml: unsupported version")
        self.sections = raw["sections"]
        self.prompts = {}
        for pid in PROMPT_IDS:
            if pid not in raw["prompt"]:
                raise MappingError(f"prompts.toml: missing prompt {pid}")
            prompt = dict(raw["prompt"][pid])
            prompt["id"] = pid
            self.prompts[pid] = prompt
        unknown = set(raw["prompt"]) - set(PROMPT_IDS)
        if unknown:
            raise MappingError(f"prompts.toml: unknown prompts {sorted(unknown)}")

    def prompt(self, pid):
        return self.prompts[pid]

    def defaults(self, pid):
        return {f["name"]: copy.deepcopy(f["default"]) for f in self.prompts[pid]["fields"] if "default" in f}

    def field(self, pid, name):
        for f in self.prompts[pid]["fields"]:
            if f["name"] == name:
                return f
        return None


class Mapping:
    def __init__(self, directory=DEFAULT_MAPPING_DIR):
        directory = Path(directory)
        self.v016 = Schema.load(directory / "schema" / "v0.16.27.json.gz")
        self.v1 = Schema.load(directory / "schema" / "v1.json.gz")
        self.v1_oss = Schema.load(directory / "schema" / "v1_oss.json.gz")
        with open(directory / "v016_to_v1.toml", "rb") as f:
            self.forward = Rules(tomllib.load(f), "v016_to_v1.toml")
        with open(directory / "normalize_016x.toml", "rb") as f:
            self.normalize = Rules(tomllib.load(f), "normalize_016x.toml")
        with open(directory / "prompts.toml", "rb") as f:
            self.catalogue = Catalogue(tomllib.load(f))
        self.pin_singletons = []
        for name, obj in sorted(self.v016.objects.items()):
            sdef = self.v016.schemas.get(name)
            if obj.get("type") != "singleton" or sdef is None or not sdef.single:
                continue
            table = self.forward.defaults.get(sdef.single, {})
            if any(policy == "pin" for policy in table.values()):
                self.pin_singletons.append(name)


def answer_get(answer, field):
    value = answer.get(field)
    return None if value is None else value


def answer_str(answer, field):
    value = answer.get(field)
    return value if isinstance(value, str) else None


def answer_bool(answer, field):
    value = answer.get(field)
    return value if isinstance(value, bool) else None


def answer_u64(answer, field):
    value = answer.get(field)
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def answer_strings(answer, field):
    value = answer.get(field)
    return [v for v in value if isinstance(v, str)] if isinstance(value, list) else []


def condition_holds(condition, answer):
    actual = answer_str(answer, condition["field"])
    if "equals" in condition:
        return actual == condition["equals"]
    return actual != condition["not_equals"]


class Answers:
    def __init__(self):
        self.global_ = {}
        self.instance = {}

    @classmethod
    def from_table(cls, root):
        answers = cls()
        for name, value in root.items():
            if name == "version":
                if value != ANSWERS_VERSION:
                    raise MappingError(f"answers: unsupported version {value}")
            elif name == "global":
                for pid, table in value.items():
                    if pid in RETIRED_PROMPT_IDS:
                        continue
                    check_prompt_id(pid)
                    answers.global_[pid] = dict(table)
            elif name == "instance":
                for pid, keys in value.items():
                    check_prompt_id(pid)
                    for key, table in keys.items():
                        parsed = ObjectKey.parse(key)
                        if parsed is None:
                            raise MappingError(f"answers: invalid object key {key}")
                        answers.instance[(pid, parsed)] = dict(table)
            else:
                raise MappingError(f"answers: unexpected key {name}")
        return answers

    @classmethod
    def load(cls, path):
        with open(path, "rb") as f:
            return cls.from_table(tomllib.load(f))

    def get(self, pid, key):
        if key is None:
            return self.global_.get(pid)
        return self.instance.get((pid, key))

    def set(self, pid, key, answer):
        if key is None:
            self.global_[pid] = answer
        else:
            self.instance[(pid, key)] = answer

    def items(self):
        for pid, answer in self.global_.items():
            yield pid, None, answer
        for (pid, key), answer in self.instance.items():
            yield pid, key, answer


def check_prompt_id(pid):
    if pid not in PROMPT_IDS:
        raise MappingError(f"answers: unknown prompt {pid}")


class Report:
    def __init__(self):
        self.entries = []
        self.questions = []

    def push(self, key, path, kind, **detail):
        self.entries.append({"key": key, "path": path, "change": kind, **detail})

    def add_question(self, question):
        for existing in self.questions:
            if existing["prompt"] == question["prompt"] and existing["key"] == question["key"]:
                return
        self.questions.append(question)

    def unanswered(self):
        return [q for q in self.questions if not q["answered"]]

    def errors(self):
        return [e for e in self.entries if e["change"] == "dangling"]


class JsonPath:
    def __init__(self):
        self.parts = []

    def push(self, segment):
        self.parts.append(segment)

    def pop(self):
        self.parts.pop()

    def text(self):
        return "/".join(self.parts)

    def child(self, segment):
        return "/".join(self.parts + [segment]) if segment else self.text()


class Options:
    def __init__(self, edition="enterprise", normalize=False, tool_questions=False,
                 external_blob_store=False, synthesize_singletons=False, owners=None):
        self.owners = owners
        self.synthesize_singletons = synthesize_singletons
        self.edition = edition
        self.normalize = normalize
        self.tool_questions = tool_questions
        self.external_blob_store = external_blob_store


class Outcome:
    def __init__(self):
        self.objects = []
        self.dropped = []
        self.report = Report()
        self.aborted = False
        self.moves = []
        self.deferred = []

    def is_complete(self):
        return not self.aborted and not self.report.unanswered() and not self.report.errors()


class Session:
    def __init__(self, mapping, answers, options, direction=FORWARD):
        if direction != FORWARD:
            raise MappingError("the plan converter only converts forward")
        self.mapping = mapping
        self.answers = answers
        self.options = options
        self.direction = direction
        given = answers.get("edition", None)
        edition = given.get("edition") if given and isinstance(given.get("edition"), str) else options.edition
        self.edition = edition if edition in ("enterprise", "oss") else options.edition
        self.rules = mapping.forward
        self.source = mapping.v016
        self.target_full = mapping.v1
        self.target = mapping.v1_oss if self.edition == "oss" else mapping.v1
        self.coordinator = None

    def answer(self, report, pid, key, defaults, context):
        given = self.answers.get(pid, key)
        answer = copy.deepcopy(defaults)
        if given is not None:
            answer.update(copy.deepcopy(given))
        report.add_question({"prompt": pid, "key": key, "defaults": defaults, "context": context,
                             "answered": given is not None})
        return answer

    def global_answer(self, report, pid):
        return self.answer(report, pid, None, self.mapping.catalogue.defaults(pid), [])

    def ask_tool_questions(self, report):
        for pid in (["blob_store"] if self.options.external_blob_store else []) + ["categories"]:
            defaults = self.mapping.catalogue.defaults(pid)
            report.add_question({"prompt": pid, "key": None, "defaults": defaults, "context": [],
                                 "answered": self.answers.get(pid, None) is not None})

    def convert_all(self, inputs, plan=None):
        outcome = Outcome()
        if self.options.tool_questions:
            self.ask_tool_questions(outcome.report)
        moves = []
        inputs = list(inputs)
        if plan is None:
            self.coordinator = coordinator_type(inputs)
            if self.coordinator is not None and all(item[0] != ObjectKey(IN_MEMORY_STORE) for item in inputs):
                inputs.append((ObjectKey(IN_MEMORY_STORE), {TYPE_KEY: IN_MEMORY_DEFAULT}))
        given = len(inputs)
        if self.options.synthesize_singletons:
            present = {item[0] for item in inputs}
            for obj in self.mapping.pin_singletons:
                if ObjectKey(obj) not in present:
                    inputs.append((ObjectKey(obj), {}))
        originals = {}
        for position, item in enumerate(inputs):
            key, value = item[0], copy.deepcopy(item[1])
            patch = len(item) > 2 and item[2]
            synthesized = position >= given
            if key.object == MERGED_OBJECT:
                originals[key] = copy.deepcopy(value)
            if self.options.normalize:
                Normalizer(self.mapping, outcome.report, key).schema_walk(key.object, value)
            walker = Walker(self, outcome.report, key, patch)
            converted = walker.convert(value)
            moves.extend(walker.moves)
            outcome.aborted = outcome.aborted or walker.abort
            if converted is None:
                outcome.dropped.append(key)
            elif synthesized and converted[1] == {}:
                pass
            else:
                obj, new_value = converted
                outcome.objects.append({"source": key, "key": key.with_object(obj), "value": new_value})
        if plan is None:
            apply_moves(moves, outcome)
        else:
            outcome.moves = moves
        finalize_all(self, outcome, originals, whole=plan is None)
        if plan is None:
            fix_dangling(self, outcome)
            sort_for_writing(self.target, outcome)
        else:
            fix_dangling(self, outcome, plan)
        return outcome


def apply_moves(moves, outcome):
    for source, obj, prop, value in moves:
        target = next((o for o in outcome.objects if o["key"].object == obj and o["key"].kind == ObjectKey.SINGLETON), None)
        if target is not None:
            if isinstance(target["value"], dict):
                target["value"][prop] = value
        else:
            outcome.objects.append({"source": source, "key": ObjectKey(obj), "value": {prop: value}})
        outcome.report.push(source, prop, "moved", to=f"{obj}.{prop}")


class Walker:
    def __init__(self, session, report, key, patch=False):
        self.patch = patch
        self.abort = False
        self.drop_expression = False
        self.session = session
        self.rules = session.rules
        self.source = session.source
        self.report = report
        self.key = key
        self.path = JsonPath()
        self.moves = []
        self.variables = ()

    def push_change(self, path, kind, **detail):
        self.report.push(self.key, path, kind, **detail)

    def dropped(self, segment, reason, value=None):
        shown = None if value is None else mask_property(segment, None, value)
        self.push_change(self.path.child(segment), "dropped", reason=reason, value=shown)

    def dropped_here(self, reason, value=None):
        self.push_change(self.path.text(), "dropped", reason=reason, value=value)

    def transformed(self, transform, segment, detail):
        self.push_change(self.path.child(segment), "transformed", transform=transform, detail=detail)

    def shown_value(self, ty, value):
        if value is None:
            return None
        return mask_property("", ty, value) if ty.is_secret() else value

    def ask(self, pid, defaults, context):
        return self.session.answer(self.report, pid, self.key, defaults, context)

    def ask_global(self, pid):
        return self.session.global_answer(self.report, pid)

    def prompt_defaults(self, pid):
        return self.session.mapping.catalogue.defaults(pid)

    def convert(self, value):
        obj = self.key.object
        rule = self.rules.objects.get(obj)
        target = rule.get("to", obj) if rule else obj
        if rule and rule.get("drop"):
            self.dropped("", DROP_NO_EQUIVALENT)
            return None
        if rule and "transform" in rule:
            output = TRANSFORMS[rule["transform"]].apply_value(self, value)
            return None if output is None else (target, output)
        if not isinstance(value, dict):
            self.dropped("", DROP_INVALID, value)
            return None
        if obj not in self.source.schemas:
            self.push_change("", "unknown")
            return target, value
        if self.walk_schema(obj, value) == KEEP:
            return target, value
        return None

    def walk_schema(self, name, value):
        sdef = self.source.schemas.get(name)
        if sdef is None:
            self.push_change(self.path.text(), "unknown")
            return KEEP
        if not isinstance(value, dict):
            return KEEP
        if sdef.single:
            return self.walk_fields(sdef.single, value)
        variant_name = value.get(TYPE_KEY)
        if not isinstance(variant_name, str):
            return KEEP
        rule = self.rules.variant(name, variant_name)
        if rule is not None:
            if rule.kind == "rename":
                value[TYPE_KEY] = rule.to
            elif rule.kind == "drop":
                self.push_change(self.path.child(TYPE_KEY), "dropped", reason=DROP_NO_EQUIVALENT, value=variant_name)
                return REMOVE
            elif rule.kind == "transform":
                output = TRANSFORMS[rule.transform].apply_value(self, dict(value))
                if output is None:
                    return REMOVE
                value.clear()
                value.update(output)
                return KEEP
        variant = sdef.variant(variant_name)
        if variant is None:
            self.push_change(self.path.child(TYPE_KEY), "unknown")
            return KEEP
        if variant[1] is None:
            return KEEP
        return self.walk_fields(variant[1], value)

    def walk_fields(self, fields_name, mapping):
        fields = self.source.fields.get(fields_name)
        if fields is None:
            return KEEP
        rules = self.rules.properties.get(fields_name)
        apply_defaults(self, fields_name, fields, mapping)
        original_order = list(mapping)
        produced = {}
        if rules:
            seen = []
            for name, rule in rules.items():
                if rule.kind != "transform":
                    continue
                transform = TRANSFORMS[rule.transform]
                always = transform.always and not self.patch
                if transform.kind != "group" or not (name in mapping or always) or rule.transform in seen:
                    continue
                seen.append(rule.transform)
                if transform.apply_group(self, mapping, produced) == REMOVE:
                    return REMOVE
        if report_strings(self, fields_name, mapping) == REMOVE:
            return REMOVE
        results = {}
        for name in sorted(mapping):
            value = mapping[name]
            if name == TYPE_KEY:
                results[name] = [(name, value)]
                continue
            rule = rules.get(name) if rules else None
            prop = fields.properties.get(name)
            if prop is None:
                if rule is None:
                    self.push_change(self.path.child(name), "unknown")
                results[name] = [(name, value)]
                continue
            self.path.push(name)
            insert = None
            if rule is None:
                flow, value = self.walk_value(prop.ty, value)
                insert = (name, value)
            elif rule.kind == "keep":
                flow, value = self.convert_then_walk(rule.convert, prop.ty, value)
                insert = (name, value)
            elif rule.kind == "rename":
                flow, value = self.convert_then_walk(rule.convert, prop.ty, value)
                insert = (rule.to, value)
            elif rule.kind == "drop":
                self.push_change(self.path.text(), "dropped", reason=DROP_NO_EQUIVALENT, value=self.shown_value(prop.ty, value))
                flow = KEEP
            elif rule.kind == "move":
                moved_flow, value = self.walk_value(prop.ty, value)
                if moved_flow == KEEP:
                    self.moves.append((self.key, rule.move[0], rule.move[1], value))
                flow = KEEP
            elif TRANSFORMS[rule.transform].kind == "property":
                previous = self.variables
                self.variables = rule.variables
                local = {}
                flow = TRANSFORMS[rule.transform].apply_property(self, name, prop.ty, value, local)
                self.variables = previous
                results[name] = list(local.items())
            else:
                flow = KEEP
                insert = (name, value)
            if self.drop_expression:
                self.drop_expression = False
                self.push_change(self.path.text(), "transformed", transform="counter_read",
                                 detail="expression dropped as answered; the v1 default applies")
                self.path.pop()
                results.pop(name, None)
                continue
            self.path.pop()
            if flow == KEEP:
                if insert is not None:
                    results[name] = [insert]
            elif prop.ty.nullable:
                if insert is not None:
                    results[name] = [(insert[0], None)]
            else:
                return REMOVE
        out = {}
        produced_written = not produced
        for name in original_order:
            if name in results:
                for key, value in results[name]:
                    out[key] = value
            elif not produced_written:
                out.update(produced)
                produced_written = True
        if not produced_written:
            out.update(produced)
        mapping.clear()
        mapping.update(out)
        return KEEP

    def walk_value(self, ty, value):
        kind = ty.kind
        if kind == "enum":
            if not isinstance(value, str):
                return KEEP, value
            found, targets = self.rules.enum_rule(ty.name, value)
            if not found:
                return KEEP, value
            if targets is None:
                self.dropped_here(DROP_NO_EQUIVALENT, value)
                return REMOVE, value
            return KEEP, targets[0]
        if kind == "object":
            if not isinstance(value, dict):
                return KEEP, value
            flow = self.walk_schema(ty.name, value)
            if flow == KEEP and ty.name == EXPRESSION_SCHEMA:
                self.rename_expression_variables(value)
            return flow, value
        if kind == "objectList":
            if not isinstance(value, dict):
                return KEEP, value
            removed = []
            for index in sorted(value):
                self.path.push(index)
                item = value[index]
                if isinstance(item, dict) and self.walk_schema(ty.name, item) == REMOVE:
                    removed.append(index)
                elif isinstance(item, dict) and ty.name == EXPRESSION_SCHEMA:
                    self.rename_expression_variables(item)
                self.path.pop()
            for index in removed:
                del value[index]
            return KEEP, value
        if kind == "set":
            if ty.cls.kind == "enum" and isinstance(value, dict):
                self.remap_enum_keys(ty.cls.name, value)
            return KEEP, value
        if kind == "map":
            if not isinstance(value, dict):
                return KEEP, value
            if ty.key.kind == "enum":
                self.remap_enum_keys(ty.key.name, value)
            removed = []
            for entry_key in sorted(value):
                self.path.push(entry_key)
                flow, new_value = self.walk_value(ty.value, value[entry_key])
                value[entry_key] = new_value
                if flow == REMOVE:
                    removed.append(entry_key)
                self.path.pop()
            for entry_key in removed:
                del value[entry_key]
            return KEEP, value
        return KEEP, value

    def remap_enum_keys(self, name, members):
        if not any(self.rules.enum_rule(name, k)[0] for k in members):
            return
        src = list(members.items())
        members.clear()
        for member, value in sorted(src, key=lambda kv: kv[0]):
            found, targets = self.rules.enum_rule(name, member)
            if found and targets is not None:
                for target in targets:
                    members.setdefault(target, value)
            elif found:
                self.push_change(self.path.child(member), "dropped", reason=DROP_NO_EQUIVALENT, value=None)
            else:
                members[member] = value

    def rename_expression_variables(self, value):
        renames = self.rules.enums.get(EXPRESSION_VARIABLES)
        functions = self.rules.functions
        if not renames and not functions:
            return

        def lookup(ident):
            targets = renames.get(ident, False) if renames else False
            return targets[0] if targets else None

        prompted = None
        for holder, key in expression_texts(value):
            for name, rule in functions.items():
                if rule[2] and rewrite_function_calls(holder[key], {name: rule}) is not None:
                    prompted = rule[2]
                    break
            if prompted:
                break
        allowed = functions
        if prompted:
            context = [("expression", holder[key]) for holder, key in expression_texts(value)]
            answer = self.ask(prompted, self.prompt_defaults(prompted), context)
            action = answer_str(answer, "action")
            if action == "abort":
                self.abort = True
                allowed = {n: r for n, r in functions.items() if not r[2]}
            elif action != "rewrite":
                self.drop_expression = True
                return
        for holder, key in expression_texts(value):
            original = holder[key]
            text = original
            if renames:
                rewritten = rename_identifiers(text, lookup)
                if rewritten is not None:
                    text = rewritten
            rewritten = rewrite_function_calls(text, allowed)
            if rewritten is not None:
                text = rewritten
            if text != original:
                if prompted:
                    self.push_change(self.path.text(), "transformed", transform="counter_read",
                                     detail=f"{original} -> {text}")
                else:
                    self.push_change(self.path.text(), "transformed", transform="expression_variables",
                                     detail=f"{original} -> {text}")
                holder[key] = text

    def convert_then_walk(self, conversion, ty, value):
        flow, value = self.convert_value(conversion, ty, value)
        if flow == REMOVE:
            return flow, value
        return self.walk_value(ty, value)

    def convert_value(self, conversion, ty, value):
        try:
            converted = convert_plain(conversion, value)
        except ValueError:
            self.dropped_here(DROP_INVALID, self.shown_value(ty, value))
            return REMOVE, value
        return KEEP, (value if converted is _UNCHANGED else converted)


_UNCHANGED = object()


def convert_plain(conversion, value):
    if conversion == "compatible" or (value is None and conversion != "string_to_public_optional"):
        return _UNCHANGED
    if conversion == "string_to_unsigned" and isinstance(value, str):
        text = value.strip()
        if not text.isdigit():
            raise ValueError(value)
        return int(text)
    if conversion == "unsigned_to_string" and is_number(value):
        return str(value)
    if conversion == "scalar_to_set" and isinstance(value, str):
        return {value: True}
    if conversion == "set_to_scalar" and isinstance(value, dict):
        return next(iter(sorted(value)), None)
    if conversion == "string_to_public_optional":
        if value is None:
            return {TYPE_KEY: "None"}
        if isinstance(value, str):
            return {TYPE_KEY: "Value", "value": value}
    return _UNCHANGED


def expression_texts(value):
    if not isinstance(value, dict):
        return []
    found = []
    items = value.get("match")
    if isinstance(items, dict):
        for index in sorted(items):
            item = items[index]
            if isinstance(item, dict):
                for key in ("if", "then"):
                    if isinstance(item.get(key), str):
                        found.append((item, key))
    if isinstance(value.get("else"), str):
        found.append((value, "else"))
    return found


def scan_identifiers(text):
    out = []
    previous = None
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch in ("'", '"'):
            quote = ch
            escaped = False
            i += 1
            while i < n:
                inner = text[i]
                i += 1
                if escaped:
                    escaped = False
                elif inner == "\\":
                    escaped = True
                elif inner == quote:
                    break
            previous = quote
            continue
        if (ch.isascii() and ch.isalpha() or ch == "_") and not (
            previous is not None and (previous.isascii() and previous.isalnum() or previous in "_$.")
        ):
            start = i
            i += 1
            while i < n and (text[i].isascii() and text[i].isalnum() or text[i] == "_"):
                i += 1
            out.append((start, i))
            previous = "_"
            continue
        previous = ch
        i += 1
    return out


def rename_identifiers(text, lookup):
    out = None
    copied = 0
    for start, end in scan_identifiers(text):
        replacement = lookup(text[start:end])
        if replacement is None:
            continue
        if out is None:
            out = []
        out.append(text[copied:start])
        out.append(replacement)
        copied = end
    if out is None:
        return None
    out.append(text[copied:])
    return "".join(out)


def matching_paren(text, open_index):
    depth = 0
    quote = None
    escaped = False
    for index in range(open_index, len(text)):
        ch = text[index]
        if quote is not None:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = None
            continue
        if ch in ("'", '"'):
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            if depth == 0:
                return None
            depth -= 1
            if depth == 0:
                return index
    return None


def rewrite_function_calls(text, functions):
    if not functions:
        return None
    edits = []
    for start, end in scan_identifiers(text):
        rule = functions.get(text[start:end])
        if rule is None:
            continue
        rest = text[end:]
        trimmed = rest.lstrip()
        if not trimmed.startswith("("):
            continue
        open_index = end + (len(rest) - len(trimmed))
        to, append = rule[0], rule[1]
        edits.append((start, end, to))
        if append:
            close = matching_paren(text, open_index)
            if close is not None:
                empty = not text[open_index + 1:close].strip()
                insertion = "".join((", " if i > 0 or not empty else "") + arg for i, arg in enumerate(append))
                edits.append((close, close, insertion))
    if not edits:
        return None
    edits.sort(key=lambda e: e[0])
    out = []
    copied = 0
    for start, end, replacement in edits:
        out.append(text[copied:start])
        out.append(replacement)
        copied = end
    out.append(text[copied:])
    return "".join(out)


def expression_mentions(value, names):
    found = []
    for holder, key in expression_texts(value):
        text = holder[key]
        for start, end in scan_identifiers(text):
            ident = text[start:end]
            if ident in names and ident not in found:
                found.append(ident)
    return found


def is_expression(ty):
    return ty.kind == "object" and ty.name == EXPRESSION_SCHEMA


def canonical_expression(value):
    if not isinstance(value, dict):
        return None
    if isinstance(value.get("default"), str):
        return ([], value["default"])
    otherwise = value.get("else")
    if not isinstance(otherwise, str):
        return None
    items = value.get("match")

    def branch(item):
        if not isinstance(item, dict) or not isinstance(item.get("if"), str) or not isinstance(item.get("then"), str):
            raise ValueError
        return (item["if"], item["then"])

    try:
        if items is None:
            branches = []
        elif isinstance(items, list):
            branches = [branch(i) for i in items]
        elif isinstance(items, dict):
            ordered = sorted(((int(k), v) for k, v in items.items()), key=lambda kv: kv[0])
            branches = [branch(v) for _, v in ordered]
        else:
            return None
    except ValueError:
        return None
    return (branches, otherwise)


def schema_defaults_equal(ty, a, b):
    if is_expression(ty):
        return canonical_expression(a) == canonical_expression(b)
    return values_equal(a, b)


def value_equals_default(ty, value, default):
    if is_expression(ty):
        current = canonical_expression(value)
        return current is not None and current == canonical_expression(default)
    return values_equal(value, default)


def default_to_wire(ty, default):
    if not is_expression(ty):
        return copy.deepcopy(default)
    canonical = canonical_expression(default)
    if canonical is None:
        return copy.deepcopy(default)
    branches, otherwise = canonical
    return {"match": {str(i): {"if": c, "then": r} for i, (c, r) in enumerate(branches)}, "else": otherwise}


def apply_defaults(w, fields_name, fields, mapping):
    if w.patch:
        return
    session = w.session
    table = session.rules.defaults.get(fields_name)
    if table is None:
        return
    rules = session.rules.properties.get(fields_name) or {}
    for name in sorted(fields.defaults):
        old_default = fields.defaults[name]
        table_policy = session.rules.default_policy(fields_name, name)
        if table_policy is None:
            continue
        prop = fields.properties.get(name)
        if prop is None:
            continue
        rule = rules.get(name)
        if rule is not None and rule.kind == "rename":
            target_fields, target_name = fields_name, rule.to
        elif rule is not None and rule.kind == "move":
            target_fields, target_name = rule.move
        elif rule is not None and rule.kind == "drop":
            continue
        else:
            target_fields, target_name = fields_name, name
        target = session.target_full.fields.get(target_fields)
        new_default = target.defaults.get(target_name) if target else None
        if new_default is not None and schema_defaults_equal(prop.ty, old_default, new_default):
            continue
        if name in mapping and not value_equals_default(prop.ty, mapping[name], old_default):
            continue
        answer = w.ask_global("changed_defaults")
        overrides = answer.get("overrides") if isinstance(answer.get("overrides"), dict) else {}
        policy = overrides.get(f"{fields_name}.{name}")
        if policy not in ("pin", "inherit"):
            policy = answer.get("policy") if answer.get("policy") in ("pin", "inherit") else table_policy
        w.path.push(name)
        if policy == "inherit" and name in mapping:
            del mapping[name]
            w.push_change(w.path.text(), "default_inherited", old=default_to_wire(prop.ty, old_default))
        elif policy == "pin":
            wire = default_to_wire(prop.ty, old_default)
            if name not in mapping:
                mapping[name] = copy.deepcopy(wire)
            w.push_change(w.path.text(), "default_pinned", value=wire)
        w.path.pop()


def is_set_secret(value):
    return isinstance(value, dict) and isinstance(value.get(TYPE_KEY), str) and value[TYPE_KEY] != "None"


def context_of(source, keys):
    return [(k, copy.deepcopy(source[k])) for k in keys if k in source]


def default_profile(url):
    rest = url.split("://", 1)[1] if "://" in url else url
    host = rest.replace(":", "/").split("/", 1)[0]
    if host == "api.openai.com":
        return "OpenAi"
    if host.endswith(".openai.azure.com"):
        return "Azure"
    return "Generic"


def base64_encode(data):
    import base64
    return base64.b64encode(data).decode("ascii")


OPENAI_TAIL = "/chat/completions"
COMMON_AI_FIELDS = ["name", "model", "timeout", "allowInvalidCerts", "httpHeaders"]
SPAM_LLM_FIELDS = ["prompt", "categories", "confidence", "separator", "responsePosCategory",
                   "responsePosConfidence", "responsePosExplanation", "temperature"]


def t_ai_model_forward(w, value):
    if not isinstance(value, dict):
        w.dropped("", DROP_INVALID, value)
        return None
    src = dict(value)
    url = src.get("url") if isinstance(src.get("url"), str) else ""
    defaults = w.prompt_defaults("ai_model_provider")
    defaults["profile"] = default_profile(url)
    defaults["url"] = url
    answer = w.ask("ai_model_provider", defaults, context_of(src, ["name", "model", "url", "modelType"]))
    provider = answer_str(answer, "provider") or "OpenAi"
    if provider == "drop":
        w.dropped("", DROP_OPERATOR)
        return None
    out = {TYPE_KEY: provider}
    for field in COMMON_AI_FIELDS:
        if field in src:
            out[field] = src.pop(field)
    given = w.session.answers.get("ai_model_provider", w.key) or {}
    new_url = answer_str(answer, "url")
    out["url"] = new_url if new_url and (given.get("url") is not None or provider == "OpenAi") else None
    if provider == "OpenAi":
        out["profile"] = answer_str(answer, "profile") or "Generic"
    if "temperature" in src:
        out["temperature"] = src.pop("temperature")
    if src.pop("modelType", None) == "Text":
        w.transformed("ai_model_union", "modelType", "text completion models are not supported by v1; migrated as a chat model")
    api_key = None
    auth = src.pop("httpAuth", None)
    if isinstance(auth, dict):
        auth_type = auth.get(TYPE_KEY)
        if auth_type == "Bearer":
            api_key = auth.get("bearerToken")
        elif auth_type == "Basic":
            username = auth.get("username") if isinstance(auth.get("username"), str) else ""
            secret = auth.get("secret")
            secret_text = secret.get("secret") if isinstance(secret, dict) and secret.get(TYPE_KEY) == "Value" else None
            if isinstance(secret_text, str) and answer_str(answer, "basic_auth") == "header":
                header = "Basic " + base64_encode(f"{username}:{secret_text}".encode())
                headers = out.setdefault("httpHeaders", {})
                if isinstance(headers, dict):
                    headers["Authorization"] = header
                w.transformed("ai_model_union", "httpAuth", "basic authentication converted to an Authorization header")
            else:
                w.dropped("httpAuth", DROP_NO_EQUIVALENT, auth)
    out["apiKey"] = api_key if api_key is not None else {TYPE_KEY: "None"}
    w.transformed("ai_model_union", "", f"converted to provider {provider}")
    return out


def t_spam_llm_forward(w, value):
    if not isinstance(value, dict):
        return None
    src = dict(value)
    if src.get(TYPE_KEY) != "Enable":
        return {TYPE_KEY: "Disable"}
    answer = w.ask("spam_ai", w.prompt_defaults("spam_ai"), context_of(src, ["modelId", "prompt", "categories"]))
    for field in SPAM_LLM_FIELDS:
        if field in src:
            w.dropped(field, DROP_NO_EQUIVALENT, src.pop(field))
    action = answer_str(answer, "action") or "defaults"
    model = src.pop("modelId", None) if "modelId" in src else None
    has_model = "modelId" in value
    if action == "disable" or not has_model:
        w.transformed("spam_llm_to_ai", "", "AI classifier left disabled")
        return {TYPE_KEY: "Disable"}
    out = {TYPE_KEY: "Enable", "tiers": {"0": {"modelId": model}}}
    if action == "custom" and answer_str(answer, "instructions") is not None:
        out["instructions"] = answer_str(answer, "instructions")
    w.transformed("spam_llm_to_ai", "", f"AI classifier enabled ({action})")
    return out


def optional_string(value):
    return value if isinstance(value, str) and value else None


def t_azure_auth_forward(w, src, out):
    access = src.pop("accessKey", None)
    sas = src.pop("sasToken", None)
    if is_set_secret(access):
        if is_set_secret(sas):
            w.dropped("sasToken", DROP_NO_EQUIVALENT, sas)
        w.transformed("azure_auth", "auth", "access key mapped to SharedKey")
        auth = {TYPE_KEY: "SharedKey", "accountKey": access}
    elif is_set_secret(sas):
        w.transformed("azure_auth", "auth", "SAS token mapped to SasToken")
        auth = {TYPE_KEY: "SasToken", "sasToken": sas}
    else:
        answer = w.ask("azure_auth", w.prompt_defaults("azure_auth"), context_of(src, ["storageAccount", "container"]))
        mode = answer_str(answer, "mode") or "ManagedIdentity"
        client_id = optional_string(answer.get("client_id"))
        tenant_id = optional_string(answer.get("tenant_id"))
        if mode == "WorkloadIdentity":
            auth = {TYPE_KEY: mode, "tenantId": tenant_id, "clientId": client_id,
                    "tokenFile": optional_string(answer.get("token_file"))}
        elif mode == "ClientSecret":
            auth = {TYPE_KEY: mode, "tenantId": tenant_id, "clientId": client_id,
                    "clientSecret": {TYPE_KEY: "Value", "secret": answer_str(answer, "client_secret") or ""}}
        else:
            auth = {TYPE_KEY: "ManagedIdentity", "clientId": client_id}
        w.transformed("azure_auth", "auth", f"authentication set to {mode} as answered")
    out["auth"] = auth
    return KEEP


def t_s3_session_token(w, src, out):
    has_session = "sessionToken" in src
    has_security = "securityToken" in src
    session = src.pop("sessionToken", None)
    security = src.pop("securityToken", None)
    if is_set_secret(session):
        if is_set_secret(security) and not json_equal(security, session):
            w.dropped("securityToken", DROP_NO_EQUIVALENT, security)
        token, present = session, True
    elif is_set_secret(security):
        w.transformed("s3_session_token", "sessionToken", "security token moved to the session token")
        token, present = security, True
    else:
        token, present = (session, True) if has_session else (security, has_security)
    if present:
        out["sessionToken"] = token
    return KEEP


def spf_mail_from_domain(src):
    results = src.get("spfResults")
    if not isinstance(results, dict):
        return None
    for result in results.values():
        if not isinstance(result, dict):
            continue
        if result.get("scope") in (None, "mfrom", "unspecified"):
            domain = result.get("domain")
            if isinstance(domain, str) and domain:
                return domain
    return None


REPORT_REQUIRED = {
    "x:DmarcReport": ("orgName", "email", "reportId", "policyDomain"),
    "x:DmarcExtension": ("definition", "name"),
    "x:DmarcDkimResult": ("domain", "selector"),
    "x:DmarcReportRecord": ("envelopeFrom", "headerFrom"),
    "x:DmarcSpfResult": ("domain",),
    "x:DmarcPolicyOverrideReason": (),
    "x:TlsReport": ("reportId",),
    "x:TlsReportPolicy": ("policyDomain",),
    "x:TlsFailureDetails": (),
    "x:ArfFeedbackReport": (),
}
REPORT_SETS = {
    "x:DmarcReport": ("errors",),
    "x:TlsReportPolicy": ("mxHosts", "policyStrings"),
    "x:ArfFeedbackReport": ("authenticationResults", "reportedDomains", "reportedUris"),
}


def report_strings(w, fields_name, mapping):
    required = REPORT_REQUIRED.get(fields_name)
    if required is None:
        return KEEP
    nulled, emptied = [], []
    for name in sorted(mapping):
        value = mapping[name]
        if value == "":
            if name in required:
                w.dropped(name, DROP_INVALID, None)
                return REMOVE
            nulled.append(name)
        elif isinstance(value, dict) and name in REPORT_SETS.get(fields_name, ()) and "" in value:
            emptied.append(name)
    for name in nulled:
        w.dropped(name, DROP_INVALID, "")
        mapping[name] = None
    for name in emptied:
        w.dropped(name, DROP_INVALID, "")
        del mapping[name][""]
    return KEEP


def t_dmarc_envelope_from(w, src, out):
    current = src.get("envelopeFrom")
    if isinstance(current, str) and current:
        return KEEP
    domain = spf_mail_from_domain(src)
    if domain is None:
        w.dropped_here(DROP_INVALID, None)
        return REMOVE
    src.pop("envelopeFrom", None)
    out["envelopeFrom"] = domain
    w.transformed(
        "dmarc_envelope_from",
        "envelopeFrom",
        "the report omitted envelope_from; derived from the SPF mfrom result domain",
    )
    return KEEP


def t_acme_description(w, src, out):
    current = src.get("description")
    if isinstance(current, str) and current:
        return KEEP
    directory = src.get("directory")
    if not isinstance(directory, str):
        return KEEP
    description = directory
    account_uri = src.get("accountUri")
    if isinstance(account_uri, str):
        account = next((segment for segment in reversed(account_uri.split("/")) if segment), None)
        if account is not None:
            description += f" ({account})"
    src.pop("description", None)
    out["description"] = description
    w.transformed(
        "acme_description",
        "description",
        "v0.16 computed the description from the directory URL and the account; v1 stores it",
    )
    return KEEP


def t_dns_sig0(w, value):
    answer = w.ask("dns_sig0", w.prompt_defaults("dns_sig0"), context_of(value, ["description", "host", "signerName"]))
    replacement = answer.get("replacement")
    if answer_str(answer, "action") == "replace" and isinstance(replacement, dict):
        w.transformed("dns_sig0", "", "replaced as answered")
        return copy.deepcopy(replacement)
    w.dropped("", DROP_NO_EQUIVALENT)
    return None


def coordinator_type(inputs):
    for item in inputs:
        if item[0] == ObjectKey(COORDINATOR):
            kind = item[1].get(TYPE_KEY) if isinstance(item[1], dict) else None
            return kind if isinstance(kind, str) and kind != COORDINATOR_DISABLED else None
    return None


def t_in_memory_cluster(w, value):
    if w.session.coordinator is None or w.key.object != IN_MEMORY_STORE:
        return value
    context = [("coordinator", w.session.coordinator)]
    answer = w.ask("in_memory_cluster", w.prompt_defaults("in_memory_cluster"), context)
    store = answer.get("store")
    if answer_str(answer, "action") == "replace" and isinstance(store, dict):
        w.transformed("in_memory_cluster", "", "replaced by the shared store as answered")
        return copy.deepcopy(store)
    return value


def t_oidc_directory_patch(w, src, out):
    if "requireScopes" in src:
        scopes = src.pop("requireScopes")
        if isinstance(scopes, dict) and scopes:
            w.dropped("requireScopes", DROP_NO_EQUIVALENT, scopes)
    if "claimName" in src:
        claim = src.pop("claimName")
        out["claimName"] = claim if isinstance(claim, str) and claim else None
    if "requireAudience" in src:
        audience = src.pop("requireAudience")
        audience_text = audience if isinstance(audience, str) and audience else None
        defaults = w.prompt_defaults("oidc_directory")
        defaults["accepted_audiences"] = [audience_text] if audience_text else []
        defaults["skip_audience_validation"] = audience_text is None
        answer = w.ask("oidc_directory", defaults, [("requireAudience", audience)])
        out["acceptedAudiences"] = {a: True for a in answer_strings(answer, "accepted_audiences")}
        out["skipAudienceValidation"] = bool(answer_bool(answer, "skip_audience_validation"))
    return KEEP


def t_oidc_directory_forward(w, src, out):
    if w.patch:
        return t_oidc_directory_patch(w, src, out)
    audience_present = "requireAudience" in src
    audience = src.pop("requireAudience", None)
    scopes_present = "requireScopes" in src
    scopes = src.pop("requireScopes", None)
    claim_present = "claimName" in src
    claim_name = src.pop("claimName", None)
    audience_text = audience if isinstance(audience, str) and audience else None
    defaults = w.prompt_defaults("oidc_directory")
    defaults["accepted_audiences"] = [audience_text] if audience_text else []
    defaults["skip_audience_validation"] = audience_text is None
    defaults["claim_name"] = claim_name if isinstance(claim_name, str) else ""
    context = []
    if "issuerUrl" in src:
        context.append(("issuerUrl", src["issuerUrl"]))
    for label, present, value in (("requireAudience", audience_present, audience),
                                  ("requireScopes", scopes_present, scopes),
                                  ("claimName", claim_present, claim_name)):
        if present:
            context.append((label, value))
    answer = w.ask("oidc_directory", defaults, context)
    if isinstance(scopes, dict) and scopes:
        w.dropped("requireScopes", DROP_NO_EQUIVALENT, scopes)
    out["acceptedAudiences"] = {a: True for a in answer_strings(answer, "accepted_audiences")}
    for prop, field in (("skipAudienceValidation", "skip_audience_validation"),
                        ("allowIdTokenClaims", "allow_id_token_claims"),
                        ("lenientIssuerMatch", "lenient_issuer_match"),
                        ("allowInvalidCerts", "allow_invalid_certs")):
        out[prop] = bool(answer_bool(answer, field))
    opaque = answer_str(answer, "opaque_token_validation") or "none"
    out["opaqueTokenValidation"] = opaque
    if opaque == "introspection":
        out["introspectionClientId"] = answer_str(answer, "introspection_client_id")
        secret = answer_str(answer, "introspection_client_secret")
        out["introspectionClientSecret"] = {TYPE_KEY: "Value", "secret": secret} if secret is not None else {TYPE_KEY: "None"}
        out["introspectionAuthMethod"] = answer_str(answer, "introspection_auth_method") or "clientSecretBasic"
    out["unscopedTokens"] = answer_str(answer, "unscoped_tokens") or "reject"
    claim = answer_str(answer, "claim_name")
    out["claimName"] = claim if claim else None
    w.transformed("oidc_directory", "", f"OIDC validation settings applied (opaque tokens {opaque})")
    return KEEP


def t_oauth_registration(w, src, out):
    values = []
    for name in ("anonymousClientRegistration", "requireClientRegistration"):
        present = name in src
        value = src.pop(name, None)
        values.append((name, present, value))
        if present:
            w.dropped(name, DROP_NO_EQUIVALENT, value)
    context = [(name, value) for name, present, value in values if present]
    answer = w.ask("oauth_registration", w.prompt_defaults("oauth_registration"), context)
    if answer_str(answer, "action") == "abort":
        w.abort = True
    return KEEP


LIFETIMES = [("authCodeExpiry", "auth_code_expiry", 600000),
             ("accessTokenExpiry", "access_token_expiry", 600000),
             ("refreshTokenExpiry", "refresh_token_expiry", 86400000)]


def t_oidc_token_lifetimes(w, src, out):
    values = []
    below = []
    for prop, _, minimum in LIFETIMES:
        present = prop in src
        value = src.pop(prop, None)
        values.append((present, value))
        if isinstance(value, int) and not isinstance(value, bool) and 0 <= value < minimum:
            below.append((prop, value))
    answer = w.ask("oidc_token_lifetimes", w.prompt_defaults("oidc_token_lifetimes"), below) if below else None
    for (prop, field, minimum), (present, value) in zip(LIFETIMES, values):
        if not present:
            continue
        if answer is not None and isinstance(value, int) and not isinstance(value, bool) and 0 <= value < minimum:
            if answer_str(answer, "action") == "set":
                replacement = max(answer_u64(answer, field) if answer_u64(answer, field) is not None else minimum, minimum)
            else:
                replacement = minimum
            w.path.push(prop)
            w.push_change(w.path.text(), "clamped", **{"from": value, "to": replacement})
            w.path.pop()
            value = replacement
        out[prop] = value
    return KEEP


def t_client_ip_source_forward(w, src, out):
    enabled = src.pop("useXForwarded", None)
    if enabled is not True:
        out["clientIpSource"] = "peer"
        return KEEP
    answer = w.ask("http_forwarded", w.prompt_defaults("http_forwarded"), [("useXForwarded", True)])
    source = answer_str(answer, "source") or "peer"
    out["clientIpSource"] = source
    if source != "peer":
        hops = answer_u64(answer, "hops")
        out["forwardedHops"] = hops if hops is not None else 1
    w.transformed("client_ip_source", "clientIpSource", f"useXForwarded replaced by {source} as answered")
    return KEEP


PERMISSION_PROPERTIES = ["enabledPermissions", "disabledPermissions", "permissions"]


def t_permissions(w, src, out):
    grant_answer = None
    for prop in PERMISSION_PROPERTIES:
        if prop not in src:
            continue
        value = src.pop(prop)
        if not isinstance(value, dict):
            out[prop] = value
            continue
        granted = [new for new, old in w.rules.grants if new not in value and any(o in value for o in old)]
        w.path.push(prop)
        w.remap_enum_keys("Permission", value)
        if granted:
            if grant_answer is None:
                grant_answer = w.ask_global("new_permissions")
            if answer_str(grant_answer, "action") == "grant":
                for permission in granted:
                    value[permission] = True
                w.transformed("permissions", "", "granted " + ", ".join(granted))
        w.path.pop()
        out[prop] = value
    return KEEP


def t_search_fields_filter(w, name, ty, value, out):
    was_empty = not isinstance(value, dict) or not value
    if ty.kind == "set" and ty.cls.kind == "enum" and isinstance(value, dict):
        w.remap_enum_keys(ty.cls.name, value)
    if not was_empty and isinstance(value, dict) and not value:
        w.transformed("search_fields_filter", "", "every indexed field was removed in v1; the v1 default applies")
        return KEEP
    out[name] = value
    return KEEP


def t_expression_removed_vars(w, name, ty, value, out):
    found = expression_mentions(value, w.variables)
    if found:
        w.transformed("expression_removed_vars", "",
                      f"uses {', '.join(found)} which v1 does not provide in this context; the v1 default applies")
        return KEEP
    flow, value = w.walk_value(ty, value)
    out[name] = value
    return flow


WEBUI_RELEASES = "https://github.com/stalwartlabs/webui/releases/"
WEBUI_LATEST = "latest/download/"
WEBUI_TAGGED = "download/"
WEBUI_LATEST_RELEASE = object()
WEBUI_DEFAULT_URL = "https://github.com/stalwartlabs/webui/releases/download/v2/webui.zip"
WEBUI_CUSTOM_BUNDLE = "webui_custom_bundle"


def webui_release(url):
    if not url.startswith(WEBUI_RELEASES):
        return None
    path = url[len(WEBUI_RELEASES):]
    if path.startswith(WEBUI_LATEST):
        return WEBUI_LATEST_RELEASE
    if not path.startswith(WEBUI_TAGGED):
        return None
    tag, sep, _ = path[len(WEBUI_TAGGED):].partition("/")
    if not sep or not tag.startswith("v"):
        return None
    return tag[1:].partition(".")[0]


def t_webui_bundle(w, name, ty, value, out):
    if isinstance(value, str):
        release = webui_release(value)
        if release == "1":
            out[name] = WEBUI_DEFAULT_URL
            w.transformed("webui_bundle", "", "official WebUI v1 bundle replaced by the v1 default WebUI v2 bundle")
            return KEEP
        if release != "2" and release is not WEBUI_LATEST_RELEASE:
            w.push_change(w.path.text(), "transformed", transform=WEBUI_CUSTOM_BUNDLE,
                          detail="custom application bundle URL kept; if it is a WebUI build, v1 only loads WebUI "
                                 "major version 2 and does not serve an older one")
    flow, value = w.walk_value(ty, value)
    out[name] = value
    return flow


def t_spam_tag(w, value):
    tag = value.get("tag") if isinstance(value, dict) else None
    if isinstance(tag, str):
        if tag.startswith(w.rules.spam_tag_removed_prefixes):
            w.dropped("", DROP_NO_EQUIVALENT, value)
            return None
        renamed = w.rules.spam_tag_renames.get(tag)
        if renamed is not None:
            value["tag"] = renamed
            w.transformed("spam_tag", "tag", f"{tag} renamed to {renamed}, the tag v1 emits")
    if not isinstance(value, dict):
        w.dropped("", DROP_INVALID, value)
        return None
    return value if w.walk_schema(w.key.object, value) == KEEP else None


class Transform:
    def __init__(self, kind, always=False, value=None, group=None, prop=None):
        self.kind = kind
        self.always = always
        self.value_fn = value
        self.group_fn = group
        self.prop_fn = prop

    def apply_value(self, w, value):
        return self.value_fn(w, value) if self.value_fn else value

    def apply_group(self, w, src, out):
        return self.group_fn(w, src, out) if self.group_fn else KEEP

    def apply_property(self, w, name, ty, value, out):
        if self.prop_fn:
            return self.prop_fn(w, name, ty, value, out)
        flow, value = w.walk_value(ty, value)
        out[name] = value
        return flow


TRANSFORMS = {
    "ai_model_union": Transform("value", value=t_ai_model_forward),
    "spam_llm_to_ai": Transform("value", value=t_spam_llm_forward),
    "dns_sig0": Transform("value", value=t_dns_sig0),
    "in_memory_cluster": Transform("value", value=t_in_memory_cluster),
    "azure_auth": Transform("group", always=True, group=t_azure_auth_forward),
    "s3_session_token": Transform("group", group=t_s3_session_token),
    "oidc_directory": Transform("group", always=True, group=t_oidc_directory_forward),
    "oidc_token_lifetimes": Transform("group", group=t_oidc_token_lifetimes),
    "oauth_registration": Transform("group", always=True, group=t_oauth_registration),
    "client_ip_source": Transform("group", group=t_client_ip_source_forward),
    "permissions": Transform("group", group=t_permissions),
    "dmarc_envelope_from": Transform("group", always=True, group=t_dmarc_envelope_from),
    "acme_description": Transform("group", always=True, group=t_acme_description),
    "search_fields_filter": Transform("property", prop=t_search_fields_filter),
    "expression_removed_vars": Transform("property", prop=t_expression_removed_vars),
    "webui_bundle": Transform("property", prop=t_webui_bundle),
    "spam_tag": Transform("value", value=t_spam_tag),
}


class Finalizer:
    def __init__(self, session, report, key):
        self.session = session
        self.target = session.target
        self.target_full = session.target_full
        self.report = report
        self.key = key
        self.path = JsonPath()
        self.enterprise_seen = False
        self.store_lost = False
        self.in_secret = False

    def reason(self, in_full_target):
        if in_full_target:
            self.enterprise_seen = True
            return DROP_ENTERPRISE
        return DROP_NOT_IN_TARGET

    def drop(self, segment, reason, value=None):
        if self.in_secret:
            value = mask_all(value)
        path = self.path.child(segment) if segment is not None else self.path.text()
        self.report.push(self.key, path, "dropped", reason=reason, value=value)

    def object(self, name, value):
        if name not in self.target.objects:
            self.drop(None, self.reason(name in self.target_full.objects))
            return REMOVE
        return self.schema(name, value)

    def schema(self, name, value):
        sdef = self.target.schemas.get(name)
        if sdef is None:
            return KEEP
        if not isinstance(value, dict):
            self.drop(None, DROP_INVALID, SECRET_MASK if name.startswith("x:Secret") else value)
            return REMOVE
        if sdef.single:
            fields = sdef.single
        else:
            variant_name = value.get(TYPE_KEY)
            if not isinstance(variant_name, str):
                self.drop(TYPE_KEY, DROP_INVALID)
                return REMOVE
            variant = sdef.variant(variant_name)
            if variant is None:
                full = self.target_full.schemas.get(name)
                in_full = full is not None and full.variant(variant_name) is not None
                reason = self.reason(in_full)
                if reason == DROP_ENTERPRISE and not self.path.parts and name in STORE_OBJECTS:
                    self.store_lost = True
                self.drop(TYPE_KEY, reason, variant_name)
                return REMOVE
            if variant[1] is None:
                for k in sorted(k for k in value if k != TYPE_KEY):
                    extra = value.pop(k)
                    self.drop(k, DROP_NOT_IN_TARGET, None if extra is None else mask_property(k, None, extra))
                return KEEP
            fields = variant[1]
        return self.fields(fields, value)

    def fields(self, fields_name, mapping):
        fields = self.target.fields.get(fields_name)
        if fields is None:
            return KEEP
        removed = []
        for name in sorted(mapping):
            if name == TYPE_KEY:
                continue
            value = mapping[name]
            prop = fields.properties.get(name)
            if prop is None:
                full_prop = self.target_full.prop(fields_name, name)
                shown = None if value is None else mask_property(name, full_prop.ty if full_prop else None, value)
                self.drop(name, self.reason(full_prop is not None), shown)
                removed.append(name)
                continue
            self.path.push(name)
            outer_secret = self.in_secret
            self.in_secret = self.in_secret or prop.ty.is_secret()
            if value is None:
                if not prop.ty.nullable:
                    self.drop(None, DROP_INVALID)
                    removed.append(name)
                flow = KEEP
            else:
                flow, value = self.value(prop.ty, value)
                mapping[name] = value
            self.in_secret = outer_secret
            self.path.pop()
            if flow == REMOVE:
                if prop.ty.nullable:
                    mapping[name] = None
                else:
                    removed.append(name)
        for name in removed:
            mapping.pop(name, None)
        return KEEP

    def value(self, ty, value):
        kind = ty.kind
        if kind == "number":
            clamped = clamp(ty, value)
            if clamped is not None:
                self.report.push(self.key, self.path.text(), "clamped", **{"from": value, "to": clamped})
                return KEEP, clamped
            return KEEP, value
        if kind == "enum":
            if not isinstance(value, str):
                return KEEP, value
            if self.target.enum_has(ty.name, value):
                return KEEP, value
            self.drop(None, self.reason(self.target_full.enum_has(ty.name, value)), value)
            return REMOVE, value
        if kind == "object":
            return self.schema(ty.name, value), value
        if kind == "objectList":
            if not isinstance(value, dict):
                return KEEP, value
            removed = []
            for index in sorted(value):
                self.path.push(index)
                if self.schema(ty.name, value[index]) == REMOVE:
                    removed.append(index)
                self.path.pop()
            for index in removed:
                del value[index]
            return KEEP, value
        if kind == "set":
            if ty.cls.kind == "enum" and isinstance(value, dict):
                self.enum_keys(ty.cls.name, value)
            return KEEP, value
        if kind == "map":
            if not isinstance(value, dict):
                return KEEP, value
            if ty.key.kind == "enum":
                self.enum_keys(ty.key.name, value)
            removed = []
            for entry_key in sorted(value):
                self.path.push(entry_key)
                entry = value[entry_key]
                if entry is not None:
                    flow, entry = self.value(ty.value, entry)
                    value[entry_key] = entry
                    if flow == REMOVE:
                        removed.append(entry_key)
                self.path.pop()
            for entry_key in removed:
                del value[entry_key]
            return KEEP, value
        return KEEP, value

    def enum_keys(self, name, members):
        for member in sorted(m for m in members if not self.target.enum_has(name, m)):
            del members[member]
            self.drop(member, self.reason(self.target_full.enum_has(name, member)))


def clamp(ty, value):
    if not is_number(value):
        return None
    current = float(value)
    minimum = ty.min
    if ty.format not in ("float", "integer"):
        minimum = max(minimum if minimum is not None else 0.0, 0.0)
    if minimum is not None and current < minimum:
        bound = minimum
    elif ty.max is not None and current > ty.max:
        bound = ty.max
    else:
        return None
    if ty.format == "float":
        return float(bound)
    if ty.format == "integer":
        return int(bound)
    return int(max(bound, 0.0))


def finalize_all(session, outcome, originals=None, whole=True):
    enterprise_seen = False
    kept = []
    for obj in outcome.objects:
        finalizer = Finalizer(session, outcome.report, obj["source"])
        flow = finalizer.object(obj["key"].object, obj["value"])
        enterprise_seen = enterprise_seen or finalizer.enterprise_seen
        outcome.aborted = outcome.aborted or finalizer.store_lost
        if flow == KEEP:
            kept.append(obj)
        else:
            outcome.dropped.append(obj["source"])
    outcome.objects = kept
    drop_lost_keys(outcome, originals or {}, whole)
    if enterprise_seen:
        answer = session.global_answer(outcome.report, "enterprise_on_oss")
        if answer_str(answer, "action") == "abort":
            outcome.aborted = True


def unique_key_value(obj, value):
    key = UNIQUE_KEYS.get(obj, ())
    if not key:
        return None
    parts = []
    for prop in key:
        part = value.get(prop) if isinstance(value, dict) else None
        if part is None:
            return None
        parts.append(f"{prop} {compact_json(part)}")
    return ", ".join(parts)


def level_of(value):
    level = value.get(MERGED_PROPERTY) if isinstance(value, dict) else None
    return level if isinstance(level, str) else MERGED_DEFAULT


def verbosity(level):
    return VERBOSITY.index(level) if level in VERBOSITY else 0


def describe_original(originals, source):
    value = originals.get(source)
    event = compact_json(value.get("event")) if isinstance(value, dict) and "event" in value else "null"
    level = level_of(value) if value is not None else MERGED_DEFAULT
    return f"event {event} at level {level}"


def object_order(key):
    return (key.object, key.kind, key.value if key.value is not None else 0)


def drop_lost_keys(outcome, originals, whole=True):
    lost = {e["key"] for e in outcome.report.entries
            if e["change"] == "dropped" and e["path"] in UNIQUE_KEYS.get(e["key"].object, ())}
    objects = outcome.objects
    order = sorted((i for i, o in enumerate(objects) if UNIQUE_KEYS.get(o["key"].object)),
                   key=lambda i: object_order(objects[i]["source"]))
    if not order:
        return
    verdicts = {}
    winners = {}
    for position in order:
        obj = objects[position]
        if obj["source"] in lost:
            verdicts[position] = ("lost",)
            continue
        text = unique_key_value(obj["key"].object, obj["value"])
        if text is None:
            if whole:
                verdicts[position] = ("lost",)
            continue
        slot = (obj["key"].object, text)
        if slot not in winners:
            winners[slot] = position
            continue
        kind = "merged" if obj["key"].object == MERGED_OBJECT else "conflict"
        verdicts[position] = (kind, text, winners[slot])
    raised = {}
    for position in sorted(verdicts):
        verdict = verdicts[position]
        if verdict[0] != "merged":
            continue
        into = verdict[2]
        level = level_of(objects[position]["value"])
        entry = raised.setdefault(into, [level_of(objects[into]["value"]), []])
        if verbosity(level) > verbosity(entry[0]):
            entry[0] = level
        entry[1].append(objects[position]["source"])
    for winner in sorted(raised):
        level, merged = raised[winner]
        obj = objects[winner]
        own = describe_original(originals, obj["source"])
        names = ", ".join(str(k) for k in merged)
        outcome.report.push(obj["source"], MERGED_PROPERTY, "transformed", transform=KEY_MERGE,
                            detail=f"kept for {names} with the same unique key, level {level} (most verbose); it was {own}")
        if isinstance(obj["value"], dict):
            obj["value"][MERGED_PROPERTY] = level
    kept = []
    for position, obj in enumerate(objects):
        verdict = verdicts.get(position)
        if verdict is None:
            kept.append(obj)
            continue
        if verdict[0] == "lost":
            reason = DROP_KEY_LOST
        elif verdict[0] == "conflict":
            reason = drop_key_conflict(verdict[1], objects[verdict[2]]["source"])
        else:
            reason = drop_merged(verdict[1], objects[verdict[2]]["source"], describe_original(originals, obj["source"]))
        outcome.report.push(obj["source"], "", "dropped", reason=reason, value=None)
        outcome.dropped.append(obj["source"])
    outcome.objects = kept


def check_value(session, schema, value):
    report = Report()
    finalizer = Finalizer(session, report, ObjectKey(schema))
    value = copy.deepcopy(value)
    if finalizer.schema(schema, value) == REMOVE and not report.entries:
        report.push(ObjectKey(schema), "", "dropped", reason=DROP_INVALID, value=None)
    return report.entries


class Fixer:
    def __init__(self, schema, present, report, key, is_missing, owners=None):
        self.owners = owners
        self.orphan = None
        self.schema = schema
        self.present = present
        self.report = report
        self.key = key
        self.path = JsonPath()
        self.pending = []
        self.is_missing = is_missing

    def absorb(self):
        for path, target, gap in self.pending:
            self.report.push(self.key, path, gap_change(gap), target=target)
        self.pending = []

    def missing(self, obj, ref):
        target = self.schema.reference_target(obj)
        if target is None or not isinstance(ref, str):
            return None
        return self.is_missing(target, ref)

    def visit_schema(self, name, value):
        sdef = self.schema.schemas.get(name)
        if sdef is None or not isinstance(value, dict):
            return KEEP
        if sdef.single:
            fields = sdef.single
        else:
            variant = sdef.variant(value.get(TYPE_KEY))
            if variant is None or variant[1] is None:
                return KEEP
            fields = variant[1]
        if self.visit_fields(fields, value) == KEEP:
            return KEEP
        marker = sdef.marker_variant() if name in MARKER_FALLBACK else None
        if marker is not None:
            value.clear()
            value[TYPE_KEY] = marker[0]
            self.absorb()
            return KEEP
        return REMOVE

    def owner(self, ty, value):
        if ty.kind != "objectId":
            return ("satisfied", None)
        found = self.missing(ty.name, value)
        if found is None or found[1] != GAP_MISSING:
            return ("satisfied", None)
        missing = found[0]
        if missing.kind != ObjectKey.ID or self.owners is None:
            return ("missing", missing)
        accounts, principals = self.owners
        if missing.value not in accounts:
            return ("orphan", missing)
        if principals == PRINCIPALS_EXCLUDED:
            return ("satisfied", None)
        return ("missing", missing)

    def visit_fields(self, fields_name, mapping):
        fields = self.schema.fields.get(fields_name)
        if fields is None:
            return KEEP
        top = self.path.text() == ""
        outside = []
        for name in sorted(mapping):
            prop = fields.properties.get(name)
            if prop is None:
                continue
            if top and name == OWNER_REFERENCE:
                verdict, account = self.owner(prop.ty, mapping[name])
                if verdict == "satisfied":
                    continue
                if verdict == "orphan":
                    self.orphan = account
                    return REMOVE
                self.pending.append((OWNER_REFERENCE, account, GAP_MISSING))
                self.pending.extend(outside)
                return REMOVE
            self.path.push(name)
            flow = self.visit_value(prop.ty, mapping[name])
            self.path.pop()
            if flow == REMOVE:
                if prop.ty.nullable:
                    mapping[name] = None
                    self.absorb()
                elif all(gap == GAP_OTHER_TENANT for _, _, gap in self.pending):
                    outside.extend(self.pending)
                    self.pending = []
                else:
                    self.pending.extend(outside)
                    return REMOVE
        if not outside:
            return KEEP
        self.pending.extend(outside)
        return REMOVE

    def visit_value(self, ty, value):
        kind = ty.kind
        if kind == "objectId":
            found = self.missing(ty.name, value)
            if found is not None:
                self.pending.append((self.path.text(), found[0], found[1]))
                return REMOVE
            return KEEP
        if kind == "set":
            if ty.cls.kind == "objectId" and isinstance(value, dict):
                self.remove_missing_keys(ty.cls.name, value)
            return KEEP
        if kind == "map":
            if not isinstance(value, dict):
                return KEEP
            if ty.key.kind == "objectId":
                self.remove_missing_keys(ty.key.name, value)
            removed = []
            for entry_key in sorted(value):
                self.path.push(entry_key)
                if self.visit_value(ty.value, value[entry_key]) == REMOVE:
                    removed.append(entry_key)
                self.path.pop()
            if removed:
                for entry_key in removed:
                    del value[entry_key]
                self.absorb()
            return KEEP
        if kind == "object":
            return self.visit_schema(ty.name, value)
        if kind == "objectList":
            if not isinstance(value, dict):
                return KEEP
            removed = []
            for index in sorted(value):
                self.path.push(index)
                if self.visit_schema(ty.name, value[index]) == REMOVE:
                    removed.append(index)
                self.path.pop()
            if not removed:
                return KEEP
            for index in removed:
                del value[index]
            if ty.min_items is not None and len(value) < ty.min_items:
                return REMOVE
            self.absorb()
            return KEEP
        return KEEP

    def remove_missing_keys(self, target, members):
        for member in sorted(members):
            found = self.missing(target, member)
            if found is not None:
                del members[member]
                self.report.push(self.key, self.path.child(member), gap_change(found[1]), target=found[0])


def gap_change(gap):
    return "reference_cleared" if gap == GAP_MISSING else "reference_outside_tenant"


def tenant_scoped(schema, obj):
    sdef = schema.schemas.get(obj)
    if sdef is None:
        return False
    names = [sdef.single] if sdef.single else [v[1] for v in sdef.variants if v[1] is not None]
    return any(TENANT_REFERENCE in schema.fields[n].properties for n in names if n in schema.fields)


def fix_dangling(session, outcome, plan=None):
    tenants = {o["key"].value for o in outcome.objects
               if o["key"].kind == ObjectKey.ID and o["key"].object == TENANT_OBJECT}

    def member_tenant(value):
        ref = value.get(TENANT_REFERENCE) if isinstance(value, dict) else None
        ident = jmap_id_parse(ref) if isinstance(ref, str) else None
        return ident if ident in tenants else None

    present = {(o["key"].object, o["key"].value): member_tenant(o["value"])
               for o in outcome.objects if o["key"].kind == ObjectKey.ID}
    scoped = {target for target, _ in present if tenant_scoped(session.target, target)}

    def checker(tenant):
        def is_missing(target, ref):
            if plan is not None:
                if ref.startswith("#") and (target, ref[1:]) in plan:
                    return (ObjectKey(target, ObjectKey.CLIENT, ref[1:]), GAP_MISSING)
                return None
            ident = jmap_id_parse(ref)
            if ident is None:
                return None
            if (target, ident) not in present:
                return (ObjectKey(target, ObjectKey.ID, ident), GAP_MISSING)
            if tenant is not None and present[(target, ident)] != tenant and target in scoped:
                return (ObjectKey(target, ObjectKey.ID, ident), GAP_OTHER_TENANT)
            return None
        return is_missing

    orphans = []
    for obj in outcome.objects:
        is_missing = checker(member_tenant(obj["value"]))
        fixer = Fixer(session.target, present, outcome.report, obj["source"], is_missing, session.options.owners)
        if fixer.visit_schema(obj["key"].object, obj["value"]) == REMOVE:
            if fixer.orphan is not None:
                outcome.report.push(obj["source"], "", "dropped", reason=drop_orphaned(fixer.orphan), value=None)
                orphans.append(obj["source"])
                continue
            for path, target, gap in fixer.pending:
                if gap == GAP_MISSING:
                    outcome.report.push(obj["source"], path, "dangling", target=target)
    if orphans:
        outcome.objects = [o for o in outcome.objects if o["source"] not in orphans]
        outcome.dropped.extend(orphans)


def collect_schema(schema, name, value, refs):
    sdef = schema.schemas.get(name)
    if sdef is None or not isinstance(value, dict):
        return
    if sdef.single:
        fields_name = sdef.single
    else:
        variant = sdef.variant(value.get(TYPE_KEY))
        fields_name = variant[1] if variant else None
    fields = schema.fields.get(fields_name) if fields_name else None
    if fields is None:
        return
    for name, item in value.items():
        prop = fields.properties.get(name)
        if prop is not None:
            collect_value(schema, prop.ty, item, refs)


def collect_value(schema, ty, value, refs):
    def push(target, ref):
        target = schema.reference_target(target)
        ident = jmap_id_parse(ref) if isinstance(ref, str) else None
        if target is not None and ident is not None:
            refs.add((target, ident))

    if ty.kind == "objectId" and isinstance(value, str):
        push(ty.name, value)
    elif ty.kind == "set" and isinstance(value, dict):
        if ty.cls.kind == "objectId":
            for ref in value:
                push(ty.cls.name, ref)
    elif ty.kind == "map" and isinstance(value, dict):
        if ty.key.kind == "objectId":
            for ref in value:
                push(ty.key.name, ref)
        for entry in value.values():
            collect_value(schema, ty.value, entry, refs)
    elif ty.kind == "object":
        collect_schema(schema, ty.name, value, refs)
    elif ty.kind == "objectList" and isinstance(value, dict):
        for item in value.values():
            collect_schema(schema, ty.name, item, refs)


def rank_of(obj):
    name = obj["key"].object
    rank = WRITE_RANK.index(name) if name in WRITE_RANK else len(WRITE_RANK)
    return (rank, name, obj["key"].sort_key())


def top_fields(schema, obj, value):
    sdef = schema.schemas.get(obj)
    if sdef is None or not isinstance(value, dict):
        return None
    if sdef.single:
        return schema.fields.get(sdef.single)
    variant = sdef.variant(value.get(TYPE_KEY))
    return schema.fields.get(variant[1]) if variant and variant[1] else None


def placeholder(schema, ty, value, pending):
    if ty.nullable:
        return True, None

    def is_pending(target, ref):
        target = schema.reference_target(target)
        ident = jmap_id_parse(ref) if isinstance(ref, str) else None
        return target is not None and ident is not None and (target, ident) in pending

    if ty.kind == "set" and isinstance(value, dict) and ty.cls.kind == "objectId":
        return True, {k: v for k, v in value.items() if not is_pending(ty.cls.name, k)}
    if ty.kind == "map" and isinstance(value, dict) and ty.key.kind == "objectId":
        return True, {k: v for k, v in value.items() if not is_pending(ty.key.name, k)}
    if ty.kind == "object":
        sdef = schema.schemas.get(ty.name)
        marker = sdef.marker_variant() if sdef else None
        if marker is not None:
            return True, {TYPE_KEY: marker[0]}
    return False, None


def cyclic_nodes(written, outgoing, edges):
    n = len(written)
    index = [None] * n
    low = [0] * n
    on_stack = [False] * n
    cyclic = [False] * n
    stack = []
    counter = 0
    for root in range(n):
        if written[root] or index[root] is not None:
            continue
        index[root] = low[root] = counter
        counter += 1
        stack.append(root)
        on_stack[root] = True
        call = [[root, 0]]
        while call:
            frame = call[-1]
            v = frame[0]
            if frame[1] < len(outgoing[v]):
                edge = edges[outgoing[v][frame[1]]]
                frame[1] += 1
                w = edge[3]
                if not edge[2] or written[w]:
                    continue
                if index[w] is None:
                    index[w] = low[w] = counter
                    counter += 1
                    stack.append(w)
                    on_stack[w] = True
                    call.append([w, 0])
                elif on_stack[w]:
                    low[v] = min(low[v], index[w])
                continue
            call.pop()
            if call:
                parent = call[-1][0]
                low[parent] = min(low[parent], low[v])
            if low[v] == index[v]:
                start = len(stack) - 1 - stack[::-1].index(v)
                component = stack[start:]
                del stack[start:]
                for w in component:
                    on_stack[w] = False
                if len(component) > 1:
                    for w in component:
                        cyclic[w] = True
    return cyclic


def sort_for_writing(schema, outcome):
    objects = outcome.objects
    index = {(o["key"].object, o["key"].value): i for i, o in enumerate(objects) if o["key"].kind == ObjectKey.ID}
    edges = []
    outgoing = [[] for _ in objects]
    incoming = [[] for _ in objects]
    blockers = [0] * len(objects)
    for i, obj in enumerate(objects):
        fields = top_fields(schema, obj["key"].object, obj["value"])
        if fields is None:
            continue
        for prop_name in sorted(obj["value"]):
            prop = fields.properties.get(prop_name)
            if prop is None:
                continue
            refs = set()
            collect_value(schema, prop.ty, obj["value"][prop_name], refs)
            for ref in sorted(refs):
                j = index.get(ref)
                if j is not None and j != i:
                    edge = len(edges)
                    edges.append([i, prop_name, True, j])
                    outgoing[i].append(edge)
                    incoming[j].append(edge)
                    blockers[i] += 1
    ready = [(rank_of(objects[i]), i) for i in range(len(objects)) if blockers[i] == 0]
    heapq.heapify(ready)
    written = [False] * len(objects)
    order = []
    breaks = []
    while len(order) < len(objects):
        if ready:
            _, i = heapq.heappop(ready)
            written[i] = True
            order.append(i)
            for e in incoming[i]:
                if edges[e][2]:
                    edges[e][2] = False
                    source = edges[e][0]
                    blockers[source] -= 1
                    if blockers[source] == 0:
                        heapq.heappush(ready, (rank_of(objects[source]), source))
            continue
        cyclic = cyclic_nodes(written, outgoing, edges)
        remaining = [i for i in range(len(objects)) if cyclic[i]]
        if not remaining:
            remaining = [i for i in range(len(objects)) if not written[i] and blockers[i] > 0]
        if not remaining:
            break
        candidate = min(remaining, key=lambda i: rank_of(objects[i]))
        properties = []
        for e in outgoing[candidate]:
            if edges[e][2]:
                edges[e][2] = False
                blockers[candidate] -= 1
                if edges[e][1] not in properties:
                    properties.append(edges[e][1])
        breaks.append((candidate, properties))
        heapq.heappush(ready, (rank_of(objects[candidate]), candidate))
    outcome.deferred = []
    for candidate, properties in breaks:
        position = order.index(candidate)
        pending = {(objects[i]["key"].object, objects[i]["key"].value) for i in order[position + 1:]
                   if objects[i]["key"].kind == ObjectKey.ID}
        obj = objects[candidate]
        fields = top_fields(schema, obj["key"].object, obj["value"])
        original = {}
        for prop_name in properties:
            if prop_name not in obj["value"]:
                continue
            prop = fields.properties.get(prop_name) if fields else None
            ok, replacement = placeholder(schema, prop.ty, obj["value"][prop_name], pending) if prop else (False, None)
            if ok:
                original[prop_name] = obj["value"][prop_name]
                obj["value"][prop_name] = replacement
                outcome.report.push(obj["source"], prop_name, "reference_deferred")
            else:
                outcome.report.push(obj["source"], prop_name, "reference_cycle")
        if original:
            outcome.deferred.append({"source": obj["source"], "key": obj["key"], "properties": original})
    outcome.objects = [objects[i] for i in order]


class Normalizer:
    def __init__(self, mapping, report, key):
        self.rules = mapping.normalize
        self.v016 = mapping.v016
        self.report = report
        self.key = key

    def changed(self, old, new):
        self.report.push(self.key, "", "transformed", transform="normalize_016x", detail=f"{old} -> {new}")

    def schema_walk(self, name, value):
        sdef = self.v016.schemas.get(name)
        if sdef is None or not isinstance(value, dict):
            return
        if sdef.single:
            fields = sdef.single
        else:
            current = value.get(TYPE_KEY)
            if not isinstance(current, str):
                return
            variant = sdef.variant(current)
            if variant is None:
                rule = self.rules.variant(name, current)
                if rule is None or rule.kind != "rename":
                    return
                variant = sdef.variant(rule.to)
                if variant is None:
                    return
                value[TYPE_KEY] = rule.to
                self.changed(current, rule.to)
            if variant[1] is None:
                return
            fields = variant[1]
        self.fields(fields, value)

    def fields(self, fields_name, mapping):
        fields = self.v016.fields.get(fields_name)
        if fields is None:
            return
        rules = self.rules.properties.get(fields_name) or {}
        for name in list(mapping):
            prop = fields.properties.get(name)
            if prop is None:
                continue
            rule = rules.get(name)
            if rule is not None and rule.kind == "keep" and not isinstance(mapping[name], dict):
                try:
                    converted = convert_plain(rule.convert, mapping[name])
                except ValueError:
                    converted = _UNCHANGED
                if converted is not _UNCHANGED:
                    self.changed(name, "object form")
                    mapping[name] = converted
            mapping[name] = self.value(prop.ty, mapping[name])

    def value(self, ty, value):
        if ty.kind == "enum":
            if isinstance(value, str):
                fixed = self.enum_value(ty.name, value)
                return value if fixed is None else fixed
        elif ty.kind == "set":
            if ty.cls.kind == "enum" and isinstance(value, dict):
                self.enum_keys(ty.cls.name, value)
        elif ty.kind == "map":
            if isinstance(value, dict):
                if ty.key.kind == "enum":
                    self.enum_keys(ty.key.name, value)
                for k in list(value):
                    value[k] = self.value(ty.value, value[k])
        elif ty.kind == "object":
            self.schema_walk(ty.name, value)
        elif ty.kind == "objectList" and isinstance(value, dict):
            for item in value.values():
                self.schema_walk(ty.name, item)
        return value

    def enum_keys(self, name, members):
        for member in list(members):
            fixed = self.enum_value(name, member)
            if fixed is not None:
                members[fixed] = members.pop(member)

    def enum_value(self, name, current):
        if self.v016.enum_has(name, current):
            return None
        found, targets = self.rules.enum_rule(name, current)
        if found and targets:
            fixed = targets[0]
        else:
            sep = self.rules.separators.get(name)
            fixed = current.replace(sep[0], sep[1]) if sep else None
            if fixed is None or not self.v016.enum_has(name, fixed):
                return None
        self.changed(current, fixed)
        return fixed


def compact_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def summary_change(entry):
    change = {"key": str(entry["key"]), "path": entry["path"], "change": entry["change"], "level": entry_level(entry)}
    if entry["change"] == "dropped":
        change["reason"] = entry.get("reason")
    return change


def outcome_summary(outcome):
    questions = sorted(
        ({"prompt": q["prompt"], "key": None if q["key"] is None else str(q["key"]), "answered": q["answered"]}
         for q in outcome.report.questions),
        key=compact_json,
    )
    changes = sorted((summary_change(e) for e in outcome.report.entries), key=compact_json)
    deduped = []
    for change in changes:
        if not deduped or deduped[-1] != change:
            deduped.append(change)
    return {
        "deferred": [{"key": str(d["key"]), "properties": d["properties"]} for d in outcome.deferred],
        "objects": [{"key": str(o["key"]), "source": str(o["source"]), "value": o["value"]} for o in outcome.objects],
        "dropped": sorted(str(k) for k in outcome.dropped),
        "questions": questions,
        "changes": deduped,
        "aborted": outcome.aborted,
    }


def run_fixture(mapping, directory):
    directory = Path(directory)
    with open(directory / "in.json", encoding="utf-8") as f:
        spec = json.load(f)
    answers = Answers()
    answers_path = directory / "answers.json"
    if answers_path.exists():
        with open(answers_path, encoding="utf-8") as f:
            answers = Answers.from_table(json.load(f))
    spec_options = spec.get("options", {})
    owners = spec.get("owners")
    if owners is not None:
        owners = ({jmap_id_parse(a) for a in owners["accounts"]}, owners["principals"])
    options = Options(edition=spec_options.get("edition", "enterprise"),
                      normalize=bool(spec_options.get("normalize", False)),
                      synthesize_singletons=bool(spec_options.get("synthesize", False)),
                      owners=owners)
    session = Session(mapping, answers, options)
    inputs = [(ObjectKey.parse(o["key"]), o["value"]) for o in spec["objects"]]
    return outcome_summary(session.convert_all(inputs))


BODY_OPS = ("create", "upsert", "reconcile")
PLAN_OPS = BODY_OPS + ("update", "destroy")


def read_plan(text):
    stripped = text.strip()
    if not stripped:
        return []
    if stripped.startswith("["):
        ops = json.loads(stripped)
        if not isinstance(ops, list):
            raise MappingError("plan: expected a JSON array")
        return ops
    ops = []
    for number, line in enumerate(text.splitlines(), 1):
        if line.strip():
            try:
                ops.append(json.loads(line))
            except json.JSONDecodeError as e:
                raise MappingError(f"plan line {number}: {e}") from e
    return ops


def write_plan(ops):
    return "".join(json.dumps(op, ensure_ascii=False, separators=(",", ":")) + "\n" for op in ops)


def style_object(original, canonical):
    return canonical if original.lower().startswith(OBJECT_PREFIX) else canonical[len(OBJECT_PREFIX):]


def instance_for(object_name, op):
    ident = op.get("id")
    if ident is None:
        return ObjectKey(object_name)
    if isinstance(ident, str) and ident.startswith("#"):
        return ObjectKey(object_name, ObjectKey.CLIENT, ident[1:])
    parsed = jmap_id_parse(ident) if isinstance(ident, str) else None
    if parsed is not None:
        return ObjectKey(object_name, ObjectKey.ID, parsed)
    return ObjectKey(object_name, ObjectKey.LABEL, str(ident))


class PlanConverter:
    def __init__(self, mapping, answers, options):
        self.mapping = mapping
        self.session = Session(mapping, answers, options)
        self.source = mapping.v016
        self.rules = mapping.forward

    def guess_variant(self, object_name, keys):
        sdef = self.source.schemas.get(object_name)
        if sdef is None or sdef.single:
            return None
        best = None
        for name, schema in sdef.variants:
            fields = self.source.fields.get(schema) if schema else None
            props = fields.properties if fields else {}
            score = sum(1 for k in keys if k in props)
            if best is None or score > best[0]:
                best = (score, name)
        return best[1] if best and best[0] > 0 else None

    def property_rule(self, object_name, variant, prop):
        sdef = self.source.schemas.get(object_name)
        if sdef is None:
            return None, None
        if sdef.single:
            candidates = [sdef.single]
        else:
            chosen = sdef.variant(variant) if variant else None
            candidates = [chosen[1]] if chosen and chosen[1] else [s for _, s in sdef.variants if s]
        for fields_name in candidates:
            fields = self.source.fields.get(fields_name)
            if fields and prop in fields.properties:
                return fields.properties[prop], (self.rules.properties.get(fields_name) or {}).get(prop)
        return None, None

    def rename_property(self, object_name, variant, prop):
        _, rule = self.property_rule(object_name, variant, prop)
        if rule is not None and rule.kind == "rename":
            return rule.to
        if rule is not None and rule.kind == "drop":
            return None
        return prop

    def enum_value(self, ty, value):
        if ty is None or ty.kind != "enum" or not isinstance(value, str):
            return value
        found, targets = self.rules.enum_rule(ty.name, value)
        if not found:
            return value
        return None if targets is None else targets[0]

    def convert(self, ops):
        bodies = {}
        patches = {}
        for index, op in enumerate(ops):
            kind = op.get("@type")
            if kind not in PLAN_OPS:
                raise MappingError(f"plan op {index + 1}: unknown op type {kind!r}")
            canonical = self.source.resolve_object(op.get("object", ""))
            if canonical is None:
                canonical = self.mapping.v1.resolve_object(op.get("object", ""))
                if canonical is None:
                    raise MappingError(f"plan op {index + 1}: unknown object {op.get('object')!r}")
            op["_canonical"] = canonical
            if kind in BODY_OPS:
                bodies[index] = []
                for client_id, body in (op.get("value") or {}).items():
                    cid = client_id[1:] if client_id.startswith("#") else client_id
                    bodies[index].append((ObjectKey(canonical, ObjectKey.CLIENT, cid), body))
            elif kind == "update":
                patch = op.get("value") or {}
                simple = {k: v for k, v in patch.items() if "/" not in k}
                sdef = self.source.schemas.get(canonical)
                if sdef is not None and sdef.variants and TYPE_KEY not in simple:
                    variant = self.guess_variant(canonical, [k.split("/", 1)[0] for k in patch])
                    if variant:
                        simple[TYPE_KEY] = variant
                        op["_guessed"] = variant
                    else:
                        op["_unguessed"] = True
                op["_key"] = instance_for(canonical, op)
                patches[index] = None if op.get("_unguessed") else simple
        self.session.coordinator = None
        for index, op in enumerate(ops):
            if op["_canonical"] != COORDINATOR:
                continue
            if op["@type"] in BODY_OPS:
                values = [body for _, body in bodies[index]]
            elif op["@type"] == "update" and patches[index] is not None:
                values = [patches[index]]
            else:
                values = []
            for value in values:
                kind = value.get(TYPE_KEY) if isinstance(value, dict) else None
                if isinstance(kind, str):
                    self.session.coordinator = None if kind == COORDINATOR_DISABLED else kind
        dropped_bodies = set()
        for index, op in enumerate(ops):
            if op["@type"] in BODY_OPS and bodies[index]:
                first = self.session.convert_all(bodies[index], plan=set())
                dropped_bodies.update((k.object, k.value) for k in first.dropped)
        report = Report()
        aborted = False
        results = {}
        moves = {}
        for index, op in enumerate(ops):
            if op["@type"] in BODY_OPS:
                inputs = bodies[index]
            elif op["@type"] == "update":
                inputs = [] if patches[index] is None else [(op["_key"], patches[index], True)]
            else:
                continue
            if not inputs:
                continue
            outcome = self.session.convert_all(inputs, plan=dropped_bodies)
            report.entries.extend(outcome.report.entries)
            for question in outcome.report.questions:
                report.add_question(question)
            aborted = aborted or outcome.aborted
            results[index] = {o["source"]: o for o in outcome.objects}
            for move in outcome.moves:
                moves.setdefault((index, move[0]), []).append(move)

        out_ops = []
        for index, op in enumerate(ops):
            kind = op["@type"]
            canonical = op.pop("_canonical")
            guessed = op.pop("_guessed", None)
            unguessed = op.pop("_unguessed", False)
            key = op.pop("_key", None)
            target_object = self.rules.objects.get(canonical, {}).get("to", canonical)
            new_op = {}
            sources = []
            for field, value in op.items():
                if field == "object":
                    new_op[field] = style_object(value, target_object)
                elif field == "value" and kind in BODY_OPS:
                    new_value = {}
                    for client_id, body in (value or {}).items():
                        cid = client_id[1:] if client_id.startswith("#") else client_id
                        body_key = ObjectKey(canonical, ObjectKey.CLIENT, cid)
                        sources.append(body_key)
                        item = results.get(index, {}).get(body_key)
                        if item is not None:
                            new_value[client_id] = self.drop_server_set(item, report)
                    new_op[field] = new_value
                elif field == "value" and kind == "update" and unguessed:
                    for name in value or {}:
                        report.push(key, name, "unknown")
                    new_op[field] = dict(value or {})
                elif field == "value" and kind == "update":
                    sources.append(key)
                    new_op[field] = self.convert_patch(canonical, guessed, key, value or {},
                                                       results.get(index, {}).get(key), report)
                elif field == "value" and kind == "destroy":
                    new_op[field] = self.convert_filter(canonical, value)
                elif field == "matchOn":
                    new_op[field] = self.convert_match_on(canonical, value)
                elif field == "scope":
                    new_op[field] = self.convert_filter(canonical, value)
                else:
                    new_op[field] = value
            if kind in BODY_OPS and op.get("value") and not new_op.get("value"):
                report.push(ObjectKey(canonical), "", "dropped", reason="every body of the op was dropped", value=None)
            else:
                out_ops.append(new_op)
            for source in sources:
                for _, obj, prop, value in moves.pop((index, source), ()):
                    self.attach_move(out_ops, ops, obj, prop, value, report, source)
        return out_ops, report, aborted

    def attach_move(self, out_ops, ops, obj, prop, value, report, source):
        for later in out_ops:
            if later.get("@type") == "update" and canonical_object(later.get("object", "")).lower() == obj.lower():
                later.setdefault("value", {})[prop] = value
                break
        else:
            name = obj if any(o.get("object", "").lower().startswith(OBJECT_PREFIX) for o in ops) else obj[len(OBJECT_PREFIX):]
            out_ops.append({"@type": "update", "object": name, "value": {prop: value}})
        report.push(source, prop, "moved", to=f"{obj}.{prop}")

    def drop_server_set(self, item, report):
        value = item["value"]
        target = self.session.target
        for fields_name in target.field_schemas(item["key"].object):
            fields = target.fields.get(fields_name)
            if fields is None:
                continue
            if target.schemas[item["key"].object].variants:
                variant = target.schemas[item["key"].object].variant(value.get(TYPE_KEY))
                if variant is None or variant[1] != fields_name:
                    continue
            for name in [n for n, p in fields.properties.items() if p.server_set and n in value]:
                report.push(item["source"], name, "dropped", reason="server-set property in a create body", value=None)
                del value[name]
        return value

    def convert_patch(self, canonical, guessed, key, patch, converted, report):
        simple = dict(converted["value"]) if converted else {}
        if guessed:
            simple.pop(TYPE_KEY, None)
        out = {}
        simple_written = False
        for name, value in patch.items():
            if "/" not in name:
                if not simple_written:
                    out.update(simple)
                    simple_written = True
                continue
            for new_name, new_value in self.convert_pointer(canonical, guessed, name, value, report, key):
                out[new_name] = new_value
        if not simple_written:
            out.update(simple)
        return out

    def convert_pointer(self, canonical, variant, pointer, value, report, key):
        head, _, rest = pointer.partition("/")
        prop, rule = self.property_rule(canonical, variant, head)
        if prop is None:
            return [(pointer, value)]
        if rule is not None and rule.kind == "drop":
            report.push(key, pointer, "dropped", reason=DROP_NO_EQUIVALENT, value=None)
            return []
        if rule is not None and (rule.kind == "move" or rule.kind == "transform" and prop.ty.kind not in ("set", "map")):
            report.push(key, pointer, "unknown")
            return [(pointer, value)]
        new_head = rule.to if rule is not None and rule.kind == "rename" else head
        results = self.convert_segments(prop.ty, rest.split("/"), value)
        if not results:
            report.push(key, pointer, "dropped", reason=DROP_NO_EQUIVALENT, value=None)
        return [("/".join([new_head] + segments), new_value) for segments, new_value in results]

    def enum_values(self, ty, value):
        if ty is None or ty.kind != "enum" or not isinstance(value, str):
            return [value]
        found, targets = self.rules.enum_rule(ty.name, value)
        if not found:
            return [value]
        return [] if targets is None else list(targets)

    def convert_segments(self, ty, segments, value):
        if not segments:
            return [([], v) for v in self.enum_values(ty, value)][:1] if ty is not None and ty.kind == "enum" else [([], value)]
        head, tail = segments[0], segments[1:]
        if ty.kind == "set":
            members = self.enum_values(ty.cls, head) if ty.cls.kind == "enum" else [head]
            return [([member] + tail, value) for member in members]
        if ty.kind == "map":
            members = self.enum_values(ty.key, head) if ty.key.kind == "enum" else [head]
            out = []
            for member in members:
                for rest, new_value in self.convert_segments(ty.value, tail, value):
                    out.append(([member] + rest, new_value))
            return out
        if ty.kind == "objectList":
            if not tail:
                return [([head], value)]
            return [([head] + rest, new_value) for rest, new_value in self.convert_nested(ty.name, tail, value)]
        if ty.kind == "object":
            return self.convert_nested(ty.name, segments, value)
        return [(segments, value)]

    def convert_nested(self, schema_name, segments, value):
        sdef = self.source.schemas.get(schema_name)
        if sdef is None:
            return [(segments, value)]
        if segments[0] == TYPE_KEY and sdef.variants:
            rule = self.rules.variant(schema_name, value) if isinstance(value, str) else None
            new_value = rule.to if rule is not None and rule.kind == "rename" else value
            return [] if rule is not None and rule.kind == "drop" else [(segments, new_value)]
        candidates = [sdef.single] if sdef.single else [schema for _, schema in sdef.variants if schema]
        for fields_name in candidates:
            fields = self.source.fields.get(fields_name)
            prop = fields.properties.get(segments[0]) if fields else None
            if prop is None:
                continue
            rule = (self.rules.properties.get(fields_name) or {}).get(segments[0])
            if rule is not None and rule.kind == "drop":
                return []
            name = rule.to if rule is not None and rule.kind == "rename" else segments[0]
            return [([name] + rest, new_value) for rest, new_value in self.convert_segments(prop.ty, segments[1:], value)]
        return [(segments, value)]

    def convert_filter(self, canonical, value):
        if not isinstance(value, dict):
            return value
        variant = value.get(TYPE_KEY) if isinstance(value.get(TYPE_KEY), str) else None
        out = {}
        for name, item in value.items():
            if name == TYPE_KEY:
                rule = self.rules.variant(canonical, item) if isinstance(item, str) else None
                out[name] = rule.to if rule is not None and rule.kind == "rename" else item
                continue
            prop, _ = self.property_rule(canonical, variant, name)
            new_name = self.rename_property(canonical, variant, name)
            if new_name is None:
                continue
            out[new_name] = self.enum_value(prop.ty if prop else None, item)
        return out

    def convert_match_on(self, canonical, value):
        if not isinstance(value, list):
            return value
        out = []
        for name in value:
            new_name = self.rename_property(canonical, None, name) if isinstance(name, str) else name
            if new_name is not None:
                out.append(new_name)
        return out


def pointer_problem(schema, schema_name, segments):
    head, tail = segments[0], segments[1:]
    if head == TYPE_KEY:
        return None
    sdef = schema.schemas.get(schema_name)
    if sdef is None:
        return None
    candidates = [sdef.single] if sdef.single else [s for _, s in sdef.variants if s]
    prop = None
    for fields_name in candidates:
        prop = schema.fields[fields_name].properties.get(head)
        if prop is not None:
            break
    if prop is None:
        return f"unknown property {head}"
    return type_path_problem(schema, prop.ty, tail, head)


def type_path_problem(schema, ty, segments, where):
    if not segments:
        return None
    head, tail = segments[0], segments[1:]
    if ty.kind == "set":
        if ty.cls.kind == "enum" and not schema.enum_has(ty.cls.name, head):
            return f"{where}/{head}: unknown value"
        return None if not tail else f"{where}/{head}: path continues past a set member"
    if ty.kind == "map":
        if ty.key.kind == "enum" and not schema.enum_has(ty.key.name, head):
            return f"{where}/{head}: unknown key"
        return type_path_problem(schema, ty.value, tail, f"{where}/{head}")
    if ty.kind == "objectList":
        return pointer_problem(schema, ty.name, tail) if tail else None
    if ty.kind == "object":
        return pointer_problem(schema, ty.name, segments)
    return f"{where}/{head}: path continues past a scalar"


def validate_plan(mapping, ops, schema):
    issues = []
    for number, op in enumerate(ops, 1):
        kind = op.get("@type")
        if kind not in PLAN_OPS:
            issues.append(f"op {number}: unknown op type {kind!r}")
            continue
        canonical = schema.resolve_object(op.get("object", ""))
        if canonical is None:
            issues.append(f"op {number}: unknown object {op.get('object')!r}")
            continue
        session = Session.__new__(Session)
        session.target = schema
        session.target_full = schema
        if kind in BODY_OPS:
            for client_id, body in (op.get("value") or {}).items():
                for entry in check_value(session, canonical, body):
                    issues.append(f"op {number} {client_id}: {entry['path'] or '(object)'}: {entry.get('reason', entry['change'])}")
                for fields_name in schema.field_schemas(canonical):
                    fields = schema.fields[fields_name]
                    for name in body if isinstance(body, dict) else ():
                        prop = fields.properties.get(name)
                        if prop is not None and prop.server_set and len(schema.field_schemas(canonical)) == 1:
                            issues.append(f"op {number} {client_id}: {name}: server-set property")
        elif kind == "update":
            for name in (op.get("value") or {}):
                problem = pointer_problem(schema, canonical, name.split("/"))
                if problem:
                    issues.append(f"op {number}: {problem}")
        for name in op.get("matchOn") or []:
            if isinstance(name, str) and name != "*":
                names = set()
                for fields_name in schema.field_schemas(canonical):
                    names.update(schema.fields[fields_name].properties)
                if name not in names:
                    issues.append(f"op {number}: matchOn property {name} is unknown")
    return issues


def masked_secrets(ops):
    found = []

    def visit(value, path):
        if isinstance(value, dict):
            for k, v in value.items():
                visit(v, path + [k])
        elif value == SECRET_MASK:
            found.append("/".join(path))

    for number, op in enumerate(ops, 1):
        visit(op.get("value"), [f"op {number}"])
    return found


def entry_level(entry):
    change = entry["change"]
    if change == "transformed" and entry.get("transform") in ("counter_read", WEBUI_CUSTOM_BUNDLE):
        return "warning"
    if change in ("dangling", "reference_cycle"):
        return "error"
    if change in ("default_pinned", "default_inherited", "transformed", "moved", "reference_deferred"):
        return "info"
    return "warning"


def entry_text(entry):
    level = entry_level(entry)
    change = entry["change"]
    head = f"{level}: {entry['key']}" + (f" {entry['path']}" if entry["path"] else "")
    if change == "dropped":
        text = f": dropped ({entry.get('reason')})"
        if entry.get("value") is not None:
            text += f", was {compact_json(entry['value'])}"
    elif change == "clamped":
        text = f": clamped {compact_json(entry['from'])} to {compact_json(entry['to'])}"
    elif change == "default_pinned":
        text = f": v0.16 default {compact_json(entry['value'])} kept (changed default pinned)"
    elif change == "default_inherited":
        text = f": v0.16 default {compact_json(entry['old'])} replaced by the new default"
    elif change == "transformed":
        text = f": {entry['transform']}: {entry['detail']}"
    elif change == "unknown":
        text = ": unknown in the source schema, kept as is"
    elif change == "reference_cleared":
        text = f": reference to {entry['target']} removed (target not migrated)"
    elif change == "reference_outside_tenant":
        text = f": reference to {entry['target']} removed (it is not in the same tenant, which v1 requires)"
    elif change == "dangling":
        text = f": references {entry['target']}, which is not migrated, and cannot be cleared"
    elif change == "moved":
        text = f": moved to {entry['to']}"
    else:
        text = f": {change}"
    return head + text


def toml_string(value):
    return json.dumps(value, ensure_ascii=False)


def toml_key(key):
    if key and all(c.isascii() and (c.isalnum() or c in "_-") for c in key):
        return key
    return toml_string(key)


def toml_inline(value):
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if is_number(value):
        return json.dumps(value)
    if isinstance(value, str):
        return toml_string(value)
    if isinstance(value, list):
        return "[" + ", ".join(v for v in (toml_inline(i) for i in value) if v is not None) + "]"
    if isinstance(value, dict):
        items = [f"{toml_key(k)} = {r}" for k, r in ((k, toml_inline(v)) for k, v in value.items()) if r is not None]
        return "{ " + ", ".join(items) + " }" if items else "{}"
    raise MappingError(f"cannot write {value!r} to TOML")


def wrapped(prefix, text):
    lines = []
    line = "# " + prefix
    for word in text.split():
        if len(line) + len(word) + 1 > WRAP and len(line) > 2:
            lines.append(line.rstrip())
            line = "#   "
        line += word + " "
    lines.append(line.rstrip())
    return lines


def write_answers(catalogue, questions, answers):
    out = ["# Answers for stalwart-migrate and cli-plan/convert_plan.py.",
           "# Written by `prepare`; it can be edited by hand. Fields left out take the",
           "# recommended value shown in the comments. Secrets are stored in clear.", "",
           f"version = {ANSWERS_VERSION}"]
    for section in catalogue.sections:
        header = False
        for pid, prompt in catalogue.prompts.items():
            if prompt["section"] != section["id"]:
                continue
            for question in [q for q in questions if q["prompt"] == pid]:
                if not header:
                    out += ["", f"# ==== {section['title']} ===="]
                    header = True
                given = answers.get(pid, question["key"])
                out.append("")
                out.append(f"# {prompt['title']}")
                out += wrapped("v0.16: ", prompt["v016"])
                out += wrapped("v1: ", prompt["v1"])
                if prompt.get("recommendation"):
                    out += wrapped("Recommendation: ", prompt["recommendation"])
                for label, value in question["context"]:
                    out.append(f"# Source {label}: {compact_json(value)}")
                for field in prompt["fields"]:
                    line = f"#   {field['name']}: {field['label']}"
                    if field.get("options"):
                        line += " (" + ", ".join(o["value"] for o in field["options"]) + ")"
                    if field["name"] in question["defaults"] and question["defaults"][field["name"]] is not None:
                        line += f"; recommended {compact_json(question['defaults'][field['name']])}"
                    out.append(line)
                if given is not None:
                    merged = copy.deepcopy(question["defaults"])
                    merged.update(given)
                    out += table_lines(prompt, question["key"], given, merged)
                else:
                    out.append("# Not answered yet: uncomment the table to accept the recommended values.")
                    out += ["# " + line for line in table_lines(prompt, question["key"], question["defaults"])]
    stale = [(pid, key, a) for pid, key, a in answers.items()
             if not any(q["prompt"] == pid and q["key"] == key for q in questions)]
    if stale:
        out += ["", "# ==== Answers that no longer apply to the source ===="]
        for pid, key, answer in stale:
            out.append("")
            out += table_lines(catalogue.prompt(pid), key, answer)
    return "\n".join(out) + "\n"


def table_lines(prompt, key, answer, scope=None):
    scope = answer if scope is None else scope
    if prompt["scope"] == "global" or key is None:
        lines = [f"[global.{prompt['id']}]"]
    else:
        lines = [f"[instance.{prompt['id']}.{toml_string(str(key))}]"]
    names = set()
    for field in prompt["fields"]:
        names.add(field["name"])
        if "when" in field and not condition_holds(field["when"], scope):
            continue
        rendered = toml_inline(answer.get(field["name"]))
        if rendered is not None:
            lines.append(f"{toml_key(field['name'])} = {rendered}")
    for name, value in answer.items():
        rendered = toml_inline(value)
        if name not in names and rendered is not None:
            lines.append(f"{toml_key(name)} = {rendered}")
    return lines


def ask_field(field, current, stream_in=input):
    kind = field["kind"]
    shown = "" if current is None else f" [{compact_json(current) if not isinstance(current, str) else current}]"
    options = field.get("options") or []
    while True:
        if options:
            for i, option in enumerate(options, 1):
                print(f"    {i}. {option['value']}: {option['label']}")
        if kind == "secret":
            import getpass
            raw = getpass.getpass(f"  {field['label']}{' [keep]' if current else ''}: ")
        else:
            raw = stream_in(f"  {field['label']}{shown}: ")
        raw = raw.strip()
        if not raw:
            return current
        try:
            return parse_field_input(field, raw)
        except ValueError as e:
            print(f"  {e}")


def parse_field_input(field, raw):
    kind = field["kind"]
    options = [o["value"] for o in field.get("options") or []]

    def choice(text):
        text = text.strip()
        if text.isdigit() and 1 <= int(text) <= len(options):
            return options[int(text) - 1]
        if text in options:
            return text
        raise ValueError(f"choose one of {', '.join(options)}")

    if kind == "choice":
        return choice(raw)
    if kind == "multi_choice":
        return [choice(t) for t in raw.split(",") if t.strip()]
    if kind == "bool":
        if raw.lower() in ("y", "yes", "true", "1"):
            return True
        if raw.lower() in ("n", "no", "false", "0"):
            return False
        raise ValueError("answer yes or no")
    if kind == "number":
        value = int(raw)
        if field.get("min") is not None and value < field["min"] or field.get("max") is not None and value > field["max"]:
            raise ValueError("out of range")
        return value
    if kind == "list":
        return [t.strip() for t in raw.split(",") if t.strip()]
    if kind in ("object", "policy_map"):
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError("expected a JSON object")
        return value
    return raw


def prepare_interactive(mapping, questions, answers, only_unanswered=True):
    catalogue = mapping.catalogue
    for question in questions:
        if only_unanswered and question["answered"]:
            continue
        prompt = catalogue.prompt(question["prompt"])
        print()
        print(f"== {prompt['title']}" + (f" ({question['key']})" if question["key"] else ""))
        print("\n".join(line[2:] for line in wrapped("v0.16: ", prompt["v016"])))
        print("\n".join(line[2:] for line in wrapped("v1: ", prompt["v1"])))
        if prompt.get("recommendation"):
            print("\n".join(line[2:] for line in wrapped("Recommendation: ", prompt["recommendation"])))
        for label, value in question["context"]:
            print(f"  source {label}: {compact_json(mask_secrets(value))}")
        answer = copy.deepcopy(question["defaults"])
        answer.update(answers.get(question["prompt"], question["key"]) or {})
        for field in prompt["fields"]:
            if field["kind"] == "policy_map":
                continue
            if "when" in field and not condition_holds(field["when"], answer):
                continue
            value = ask_field(field, answer.get(field["name"]))
            if value is not None:
                answer[field["name"]] = value
        answers.set(question["prompt"], question["key"], answer)
    return answers


def validate_answers(mapping, questions, answers):
    issues = []
    for question in questions:
        given = answers.get(question["prompt"], question["key"])
        scope = f" for {question['key']}" if question["key"] else ""
        if given is None:
            issues.append(f"{question['prompt']}{scope}: not answered")
            continue
        merged = copy.deepcopy(question["defaults"])
        merged.update(given)
        prompt = mapping.catalogue.prompt(question["prompt"])
        for name in given:
            if mapping.catalogue.field(question["prompt"], name) is None:
                issues.append(f"{question['prompt']}{scope}: unknown field {name}")
        for field in prompt["fields"]:
            if "when" in field and not condition_holds(field["when"], merged):
                continue
            value = merged.get(field["name"])
            required = field_required(field, merged)
            if required and (isinstance(value, str) and not value.strip() or value == []):
                value = None
            if value is None:
                if required:
                    issues.append(f"{question['prompt']}{scope}: {field['name']} is required")
                continue
            try:
                check_field_value(field, value)
            except ValueError as e:
                issues.append(f"{question['prompt']}{scope}: {field['name']}: {e}")
                continue
            if field["kind"] == "object":
                session = Session(mapping, Answers(), Options())
                entries = check_value(session, field["schema"], value)
                if entries:
                    issues.append(f"{question['prompt']}{scope}: {field['name']}: {entry_text(entries[0])}")
    return issues


def field_required(field, answer):
    required = field.get("required", False)
    if required is True or isinstance(required, dict) and condition_holds(required, answer):
        return True
    return "default" not in field and field["kind"] not in ("secret", "string", "list")


def write_private(path, text):
    import os
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.chmod(path, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)


def check_field_value(field, value):
    kind = field["kind"]
    options = [o["value"] for o in field.get("options") or []]
    if kind == "choice" and value not in options:
        raise ValueError(f"{value} is not one of the options")
    if kind == "multi_choice" and (not isinstance(value, list) or any(v not in options for v in value)):
        raise ValueError("not a list of options")
    if kind == "bool" and not isinstance(value, bool):
        raise ValueError("expected true or false")
    if kind == "number":
        if not is_number(value):
            raise ValueError("expected a number")
        if field.get("min") is not None and value < field["min"] or field.get("max") is not None and value > field["max"]:
            raise ValueError(f"{value} is out of range")
    if kind in ("string", "secret") and not isinstance(value, str):
        raise ValueError("expected a string")
    if kind == "list" and (not isinstance(value, list) or not all(isinstance(v, str) for v in value)):
        raise ValueError("expected a list of strings")
    if kind in ("object", "policy_map") and not isinstance(value, dict):
        raise ValueError("expected an object")


def already_converted(mapping, ops):
    if not ops:
        return False
    return not validate_plan(mapping, copy.deepcopy(ops), mapping.v1) and bool(
        validate_plan(mapping, copy.deepcopy(ops), mapping.v016))


def run_conversion(mapping, ops, answers, options):
    converter = PlanConverter(mapping, answers, options)
    return converter.convert(copy.deepcopy(ops))


def cmd_prepare(args, mapping):
    ops = read_plan(Path(args.plan).read_text(encoding="utf-8"))
    answers_path = Path(args.answers) if args.answers else Path(args.plan).with_suffix(".answers.toml")
    answers = Answers.load(answers_path) if answers_path.exists() else Answers()
    options = Options(normalize=True)
    _, report, _ = run_conversion(mapping, ops, answers, options)
    prepare_interactive(mapping, report.questions, answers, only_unanswered=not args.all)
    _, report, _ = run_conversion(mapping, ops, answers, options)
    write_private(answers_path, write_answers(mapping.catalogue, report.questions, answers))
    print(f"answers written to {answers_path}")
    return 0


def cmd_convert(args, mapping):
    plan_path = Path(args.plan)
    text = plan_path.read_text(encoding="utf-8")
    ops = read_plan(text)
    output = Path(args.output)
    if already_converted(mapping, ops):
        print("plan already uses the v1 schema; nothing to convert", file=sys.stderr)
        output.write_text(write_plan(ops), encoding="utf-8")
        return 0
    answers_path = Path(args.answers) if args.answers else output.with_suffix(".answers.toml")
    answers = Answers.load(answers_path) if answers_path.exists() else Answers()
    options = Options(normalize=True)
    out_ops, report, aborted = run_conversion(mapping, ops, answers, options)
    if report.unanswered() and sys.stdin.isatty() and not args.strict:
        prepare_interactive(mapping, report.questions, answers)
        out_ops, report, aborted = run_conversion(mapping, ops, answers, options)
    unanswered = report.unanswered()
    if unanswered and args.strict:
        for question in unanswered:
            print(f"unanswered: {question['prompt']}" + (f" for {question['key']}" if question["key"] else ""), file=sys.stderr)
        return 2
    if aborted:
        print("stopped: enterprise-only settings and an open source target (enterprise_on_oss = abort)", file=sys.stderr)
        return 2
    issues = validate_answers(mapping, [q for q in report.questions if q["answered"]], answers)
    if issues:
        for issue in issues:
            print(f"answers: {issue}", file=sys.stderr)
        return 2
    lines = [entry_text(e) for e in report.entries]
    lines += [f"default applied: {q['prompt']}" + (f" for {q['key']}" if q["key"] else "") for q in unanswered]
    lines += [f"warning: masked secret at {path} cannot be converted; set it after applying" for path in masked_secrets(ops)]
    output.write_text(write_plan(out_ops), encoding="utf-8")
    write_private(answers_path, write_answers(mapping.catalogue, report.questions, answers))
    report_text = "\n".join(lines) + ("\n" if lines else "")
    if args.report:
        Path(args.report).write_text(report_text, encoding="utf-8")
    else:
        sys.stderr.write(report_text)
    edition = Session(mapping, answers, options).edition
    validation = validate_plan(mapping, copy.deepcopy(out_ops), mapping.v1_oss if edition == "oss" else mapping.v1)
    for issue in validation:
        print(f"validation: {issue}", file=sys.stderr)
    return 1 if validation or report.errors() else 0


def cmd_validate(args, mapping):
    ops = read_plan(Path(args.plan).read_text(encoding="utf-8"))
    schema = mapping.v1_oss if args.oss else mapping.v1
    issues = validate_plan(mapping, ops, schema)
    for issue in issues:
        print(issue)
    if not issues:
        print("plan is valid for the v1 schema")
    return 1 if issues else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--mapping-dir", default=str(DEFAULT_MAPPING_DIR))
    sub = parser.add_subparsers(dest="command", required=True)
    prepare = sub.add_parser("prepare", help="answer the questions a plan needs")
    prepare.add_argument("plan")
    prepare.add_argument("--answers")
    prepare.add_argument("--all", action="store_true", help="ask answered questions again")
    convert = sub.add_parser("convert", help="convert a v0.16 plan to v1")
    convert.add_argument("plan")
    convert.add_argument("-o", "--output", required=True)
    convert.add_argument("--answers")
    convert.add_argument("--report")
    convert.add_argument("--strict", action="store_true", help="fail on unanswered questions instead of applying defaults")
    validate = sub.add_parser("validate", help="check a plan against the v1 schema")
    validate.add_argument("plan")
    validate.add_argument("--oss", action="store_true", help="validate against the open source schema")
    args = parser.parse_args(argv)
    try:
        mapping = Mapping(args.mapping_dir)
        return {"prepare": cmd_prepare, "convert": cmd_convert, "validate": cmd_validate}[args.command](args, mapping)
    except (MappingError, OSError, json.JSONDecodeError, tomllib.TOMLDecodeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
