#!/usr/bin/env python3
"""Generate pygeoapi resource config from SOSI plan XMI models."""

from __future__ import annotations

import argparse
import html
import re
import sys
import unicodedata
import urllib.request
from urllib.parse import quote, urlsplit, urlunsplit
import defusedxml.ElementTree as ET
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple, cast

UML_NAMESPACES = (
    "http://www.omg.org/spec/UML/20131001",
    "http://www.nomagic.com/magicdraw/UML/2.5.1.1",
    "omg.org/UML1.3",
)
UML_NS = UML_NAMESPACES[0]
NS = {"UML": UML_NS}
XMI_NS = "http://www.omg.org/spec/XMI/20131001"
XMI_ID = f"{{{XMI_NS}}}id"
XMI_IDREF = f"{{{XMI_NS}}}idref"
XMI_TYPE = f"{{{XMI_NS}}}type"

NORWEGIAN_TRANSLATION = str.maketrans(
    {
        "\u00e6": "ae",
        "\u00c6": "AE",
        "\u00f8": "oe",
        "\u00d8": "OE",
        "\u00e5": "aa",
        "\u00c5": "AA",
    }
)


def translate_norwegian(text: str) -> str:
    return text.translate(NORWEGIAN_TRANSLATION)


def _get_xmi_attr(node: ET.Element, local_name: str) -> Optional[str]:
    return (
        node.get(f"{{{XMI_NS}}}{local_name}")
        or node.get(f"xmi.{local_name}")
        or node.get(f"xmi:{local_name}")
    )


def get_xmi_id(node: ET.Element) -> Optional[str]:
    return _get_xmi_attr(node, "id")


def get_xmi_idref(node: ET.Element) -> Optional[str]:
    return _get_xmi_attr(node, "idref")


def get_xmi_type(node: ET.Element) -> Optional[str]:
    return _get_xmi_attr(node, "type")


def iter_elements_by_type(root: ET.Element, local_name: str) -> Iterator[ET.Element]:
    seen: Set[int] = set()
    for namespace in UML_NAMESPACES:
        tag = f"{{{namespace}}}{local_name}"
        for node in root.findall(f".//{tag}"):
            node_id = id(node)
            if node_id in seen:
                continue
            seen.add(node_id)
            yield node
    target_type = f"uml:{local_name}"
    for node in root.iter():
        if get_xmi_type(node) == target_type:
            node_id = id(node)
            if node_id in seen:
                continue
            seen.add(node_id)
            yield node

OBJID_FIELD = {
    "id": "objid",
    "title": "Objekt ID",
    "description": "l\u00f8pende lokal identifikator for objektet.",
}


class TransformationError(RuntimeError):
    """Raised when the transformation cannot be completed."""


class Model:
    """Convenience wrapper that indexes the XMI content."""

    def __init__(self, root: ET.Element) -> None:
        self.root = root
        self.classes_by_id: Dict[str, ET.Element] = {}
        self.classes_by_name: Dict[str, ET.Element] = {}

        for cls in iter_elements_by_type(root, "Class"):
            class_id = get_xmi_id(cls)
            if class_id:
                self.classes_by_id[class_id] = cls
            name = cls.get("name")
            if not name:
                continue
            existing = self.classes_by_name.get(name)
            if existing is None:
                self.classes_by_name[name] = cls
                continue
            if class_has_attributes(cls) and not class_has_attributes(existing):
                self.classes_by_name[name] = cls

        self.enumerations_by_id: Dict[str, ET.Element] = {}
        self.enumerations_by_name: Dict[str, ET.Element] = {}
        for enum in iter_elements_by_type(root, "Enumeration"):
            enum_id = get_xmi_id(enum)
            if enum_id:
                self.enumerations_by_id[enum_id] = enum
            name = enum.get("name")
            if name and name not in self.enumerations_by_name:
                self.enumerations_by_name[name] = enum

        self.generalizations: Dict[str, List[str]] = {}
        for relation in root.findall(".//UML:Generalization", NS):
            subtype = relation.get("subtype")
            supertype = relation.get("supertype")
            if subtype and supertype:
                self.generalizations.setdefault(subtype, []).append(supertype)

    def class_by_name(self, name: str) -> ET.Element:
        try:
            return self.classes_by_name[name]
        except KeyError as exc:
            raise TransformationError(f"Fant ikke klassen {name!r} i XMI-filen") from exc

    def class_by_id(self, class_id: Optional[str]) -> Optional[ET.Element]:
        if not class_id:
            return None
        return self.classes_by_id.get(class_id)

    def enumeration_literals(self, type_id: Optional[str], type_name: Optional[str]) -> List[str]:
        nodes: List[ET.Element] = []
        if type_id:
            node = self.classes_by_id.get(type_id)
            if node is not None:
                nodes.append(node)
            enum_node = self.enumerations_by_id.get(type_id)
            if enum_node is not None:
                nodes.append(enum_node)
        if type_name:
            node = self.classes_by_name.get(type_name)
            if node is not None and node not in nodes:
                nodes.append(node)
            enum_node = self.enumerations_by_name.get(type_name)
            if enum_node is not None and enum_node not in nodes:
                nodes.append(enum_node)

        literals: List[str] = []
        for node in nodes:
            stereotype = get_stereotype(node).lower()
            if node.tag.endswith("}Enumeration"):
                literals.extend(_enumeration_literals_from_enum(node))
            elif stereotype == "enumeration":
                literals.extend(_enumeration_literals_from_class(node))
        seen: Set[str] = set()
        unique_literals: List[str] = []
        for value in literals:
            if value is None:
                continue
            if value in seen:
                continue
            seen.add(value)
            unique_literals.append(value)
        return unique_literals


def class_has_attributes(node: ET.Element) -> bool:
    features = node.find("UML:Classifier.feature", NS)
    if features is None:
        return False
    return features.find("UML:Attribute", NS) is not None


def should_expand_attribute(node: ET.Element) -> bool:
    if not class_has_attributes(node):
        return False
    stereotype = get_stereotype(node).lower()
    return stereotype in {"datatype", "union"}


def clean_text(value: Optional[str]) -> str:
    """Collapse whitespace and decode entities."""
    if not value:
        return ""
    text = html.unescape(value)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def yaml_quote(value: str) -> str:
    """Return a single-quoted YAML scalar."""
    return "'" + value.replace("'", "''") + "'"


def normalize_url(url: str) -> str:
    """Percent-encode URL components that may contain spaces or non-ASCII characters."""
    parts = urlsplit(url)
    path = quote(parts.path, safe="/%")
    query = quote(parts.query, safe="=&%")
    fragment = quote(parts.fragment, safe="/%")
    return urlunsplit((parts.scheme, parts.netloc, path, query, fragment))


def _enumeration_literals_from_enum(node: ET.Element) -> List[str]:
    values: List[str] = []
    for literal in node.findall("UML:Enumeration.literal/UML:EnumerationLiteral", NS):
        name = literal.get("name")
        if name:
            values.append(name)
    return values


def _enumeration_literals_from_class(node: ET.Element) -> List[str]:
    values: List[str] = []
    features = node.find("UML:Classifier.feature", NS)
    if features is None:
        return values
    for attr in features.findall("UML:Attribute", NS):
        name = attr.get("name")
        if name:
            values.append(name)
    return values


def slugify(name: str) -> str:
    normalized = unicodedata.normalize("NFKD", translate_norwegian(name))
    ascii_name = normalized.encode("ascii", "ignore").decode("ascii")
    slug = re.sub(r"[^A-Za-z0-9]+", "_", ascii_name).strip("_")
    if not slug:
        raise TransformationError(f"Kan ikke lage nøkkel for navnet {name!r}")
    return slug.lower()


def fetch_xmi_bytes(url: str, username: str, password: str) -> bytes:
    url = normalize_url(url)
    password_mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    password_mgr.add_password(None, url, username, password)
    handler = urllib.request.HTTPBasicAuthHandler(password_mgr)
    opener = urllib.request.build_opener(handler)
    with opener.open(url) as response:
        return response.read()


def extract_tagged_values(node: ET.Element) -> Dict[str, str]:
    values: Dict[str, str] = {}
    for tagged_value in node.findall("UML:ModelElement.taggedValue/UML:TaggedValue", NS):
        tag = tagged_value.get("tag")
        if not tag:
            continue
        values[tag] = tagged_value.get("value", "")
    return values


def get_stereotype(node: ET.Element) -> str:
    stereotype = node.find("UML:ModelElement.stereotype/UML:Stereotype", NS)
    if stereotype is not None:
        stereo_name = stereotype.get("name") or get_xmi_idref(stereotype)
        if stereo_name:
            return stereo_name
    tagged = extract_tagged_values(node)
    return tagged.get("stereotype", "")


def get_class_documentation(node: ET.Element) -> str:
    tagged = extract_tagged_values(node)
    return clean_text(tagged.get("documentation"))


def attribute_type_reference(attribute: ET.Element) -> Optional[str]:
    type_node = attribute.find("UML:StructuralFeature.type/UML:Classifier", NS)
    if type_node is None:
        return None
    return get_xmi_idref(type_node)


def collect_attribute_paths(
    model: Model,
    class_name: str,
    prefix: Sequence[str] = (),
    super_visited: Optional[Set[str]] = None,
    type_visited: Optional[Set[str]] = None,
) -> Iterator[Tuple[Tuple[str, ...], ET.Element]]:
    super_visited = set() if super_visited is None else set(super_visited)
    type_visited = set() if type_visited is None else set(type_visited)

    class_node = model.class_by_name(class_name)
    class_id = get_xmi_id(class_node)
    if class_id and class_id in super_visited:
        return
    if class_id:
        super_visited.add(class_id)

    for super_id in model.generalizations.get(class_id or "", []):
        super_node = model.class_by_id(super_id)
        if super_node is None:
            continue
        super_name = super_node.get("name")
        if not super_name:
            continue
        yield from collect_attribute_paths(model, super_name, prefix, super_visited, type_visited)

    features = class_node.find("UML:Classifier.feature", NS)
    if features is None:
        return

    for attribute in features.findall("UML:Attribute", NS):
        attr_name = attribute.get("name")
        if not attr_name:
            continue
        path = tuple(prefix) + (attr_name,)
        type_id = attribute_type_reference(attribute)
        type_node = model.class_by_id(type_id)
        if type_node is not None and should_expand_attribute(type_node):
            if type_id and type_id in type_visited:
                continue
            type_name = type_node.get("name")
            if not type_name:
                continue
            new_type_visited = set(type_visited)
            if type_id:
                new_type_visited.add(type_id)
            yield from collect_attribute_paths(model, type_name, path, super_visited, new_type_visited)
            continue
        yield path, attribute


def build_fields_for_class(
    model: Model, class_name: str
) -> List[Dict[str, object]]:
    fields: List[Dict[str, object]] = []
    used_ids: Set[str] = set()

    for path, attribute in collect_attribute_paths(model, class_name):
        attribute_name = path[-1]
        type_id = attribute_type_reference(attribute)
        tags = extract_tagged_values(attribute)
        description = clean_text(tags.get("description"))
        type_name = tags.get("type")

        if not description:
            type_node = model.class_by_id(type_id)
            if type_node is not None:
                description = get_class_documentation(type_node)
        if not description:
            description = attribute_name

        codelist = clean_text(tags.get("defaultCodeSpace"))

        enum_values = model.enumeration_literals(type_id, type_name)

        field_id = translate_norwegian(attribute_name)
        if not field_id or not field_id.strip():
            field_id = attribute_name
        if not field_id.strip():
            field_id = slugify(attribute_name)

        if field_id in used_ids:
            candidate_parts = [translate_norwegian(part) for part in path]
            candidate = "_".join(candidate_parts)
            if not candidate.strip():
                candidate = slugify(".".join(path))
            if candidate in used_ids:
                suffix = 2
                while f"{candidate}_{suffix}" in used_ids:
                    suffix += 1
                candidate = f"{candidate}_{suffix}"
            field_id = candidate
        used_ids.add(field_id)

        title = ".".join(path) if len(path) > 1 else path[0]
        field = {
            "id": field_id,
            "title": title,
            "description": description,
        }
        if codelist:
            field["codelist"] = codelist
        if enum_values:
            field["enum"] = enum_values
        fields.append(field)

    return fields


def build_resources(model: Model) -> List[Dict[str, object]]:
    feature_types = [
        name
        for name, node in model.classes_by_name.items()
        if get_stereotype(node).lower() == "featuretype"
        and node.get("isAbstract", "").lower() != "true"
    ]
    if not feature_types:
        feature_types = [
            name
            for name, node in model.classes_by_name.items()
            if node.get("isAbstract", "").lower() != "true"
        ]

    resources: List[Dict[str, object]] = []
    used_keys: Set[str] = set()

    for name in sorted(feature_types):
        class_node = model.class_by_name(name)
        description = get_class_documentation(class_node) or name
        fields = [OBJID_FIELD.copy()] + build_fields_for_class(model, name)

        key_base = slugify(name)
        key = key_base
        suffix = 2
        while key in used_keys:
            key = f"{key_base}_{suffix}"
            suffix += 1
        used_keys.add(key)

        resource = {
            "key": key,
            "title": name,
            "description": description,
            "table": key,
            "fields": fields,
        }
        resources.append(resource)
    return resources


def render_yaml(resources: Iterable[Dict[str, object]]) -> str:
    def add_line(buffer: List[str], indent: int, text: str) -> None:
        buffer.append("  " * indent + text)

    resources = list(resources)
    if not resources:
        raise TransformationError("Fant ingen realiserbare typer (FeatureType) i modellen.")

    lines: List[str] = []
    add_line(lines, 0, "resources:")
    for resource in resources:
        add_line(lines, 1, f"{resource['key']}:")
        add_line(lines, 2, "type: collection")
        add_line(lines, 2, f"title: {yaml_quote(str(resource['title']))}")
        add_line(lines, 2, f"description: {yaml_quote(str(resource['description']))}")
        add_line(lines, 2, "providers:")
        add_line(lines, 3, "- type: feature")
        add_line(lines, 4, "name: postgresql_ext.PostgreSQLExtendedProvider")
        add_line(lines, 4, "id_field: objid")
        add_line(lines, 4, f"table: {resource['table']}")
        add_line(lines, 4, "fields:")
        fields = cast(List[Dict[str, object]], resource["fields"])
        for field_dict in fields:
            add_line(lines, 5, f"{field_dict['id']}:")
            add_line(lines, 6, f"title: {yaml_quote(str(field_dict['title']))}")
            add_line(lines, 6, f"description: {yaml_quote(str(field_dict['description']))}")
            codelist = field_dict.get("codelist")
            if codelist:
                add_line(lines, 6, f"codelist: {yaml_quote(str(codelist))}")
            enum_values = field_dict.get("enum")
            if enum_values:
                if isinstance(enum_values, (list, tuple)):
                    enum_str = ", ".join(f"\"{str(value)}\"" for value in enum_values)
                else:
                    enum_str = f"\"{enum_values}\""
                add_line(lines, 6, f"enum: [{enum_str}]")
        lines.append("")
    return "\n".join(lines)


def parse_arguments(argv: Optional[Iterable[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Fetch a SOSI XMI model and generate a pygeoapi configuration with one resource per realisable type."
        )
    )
    parser.add_argument(
        "--url",
        help="URL til XMI-modellen (brukes dersom --xmi ikke er satt).",
    )
    parser.add_argument(
        "--username",
        default="sosi",
        help="Brukernavn for autentisering mot SOSI-repositoriet (standard: sosi).",
    )
    parser.add_argument(
        "--password",
        default="sosi",
        help="Passord for autentisering (standard: sosi).",
    )
    parser.add_argument(
        "--xmi",
        type=Path,
        help="Les XMI fra lokal fil i stedet for å laste ned.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Filsti for generert YAML. Hvis utelatt, brukes navnet til XMI-filen.",
    )
    return parser.parse_args(argv)


def main(argv: Optional[Iterable[str]] = None) -> int:
    args = parse_arguments(argv)

    if not args.xmi and not args.url:
        raise TransformationError("Oppgi enten --xmi eller --url for å hente XMI-modellen.")

    if args.xmi:
        data = args.xmi.read_bytes()
    else:
        url = cast(str, args.url)
        data = fetch_xmi_bytes(url, args.username, args.password)

    root = ET.fromstring(data)
    model = Model(root)
    resources = build_resources(model)
    yaml_text = render_yaml(resources)

    output_path = args.output
    if output_path is None:
        if args.xmi:
            output_path = args.xmi.with_suffix(".yaml")
        else:
            url_path = Path(urlsplit(cast(str, args.url)).path)
            stem = url_path.stem or "pygeoapi_config"
            output_path = Path(f"{stem}.yaml")

    output_path.write_text(yaml_text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except TransformationError as exc:
        print(f"Feil under transformasjon: {exc}", file=sys.stderr)
        sys.exit(1)
