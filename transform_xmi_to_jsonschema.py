#!/usr/bin/env python3
"""Generate JSON Schema files from SOSI solution model XMI packages."""

from __future__ import annotations

import argparse
import copy
import html
import json
import re
import sys
import unicodedata
import urllib.request
from urllib.parse import urlparse
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple

XMI_NS = "http://www.omg.org/spec/XMI/20131001"
XSI_NS = "http://www.w3.org/2001/XMLSchema-instance"
UML_NS = "http://www.omg.org/spec/UML/20131001"
BR_NS = "http://www.magicdraw.com/schemas/BRProfil.xmi"

NS = {"xmi": XMI_NS, "uml": UML_NS, "br": BR_NS}

XSI_TYPE = f"{{{XSI_NS}}}type"

PRIMITIVE_TYPE_MAP: Dict[str, Dict[str, Any]] = {
    "string": {"type": "string"},
    "boolean": {"type": "boolean"},
    "integer": {"type": "integer"},
    "number": {"type": "number"},
    "decimal": {"type": "number"},
    "date": {"type": "string", "format": "date"},
    "datetime": {"type": "string", "format": "date-time"},
    "time": {"type": "string", "format": "time"},
    "anyuri": {"type": "string", "format": "uri"},
    "gyear": {"type": "string", "pattern": r"^\d{4}$"},
    "gyearmonth": {"type": "string", "pattern": r"^\d{4}-(0[1-9]|1[0-2])$"},
    "base64binary": {
        "type": "string",
        "pattern": r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$",
    },
    "hexbinary": {"type": "string", "pattern": r"^(?:[0-9a-fA-F]{2})*$"},
    "token": {"type": "string"},
    "int": {"type": "integer", "minimum": -2147483648, "maximum": 2147483647},
    "short": {"type": "integer", "minimum": -32768, "maximum": 32767},
    "long": {
        "type": "integer",
        "minimum": -9223372036854775808,
        "maximum": 9223372036854775807,
    },
    "negativeinteger": {"type": "integer", "maximum": -1},
    "nonpositiveinteger": {"type": "integer", "maximum": 0},
    "positiveinteger": {"type": "integer", "minimum": 1},
    "nonnegativeinteger": {"type": "integer", "minimum": 0},
}

HTML_TAG_RE = re.compile(r"<[^>]+>")
ANCHOR_TEXT_RE = re.compile(r"<a\b[^>]*>(.*?)</a>", re.IGNORECASE | re.DOTALL)
WHITESPACE_RE = re.compile(r"\s+")

XMI_NAMESPACES = (
    "http://www.omg.org/spec/XMI/20131001",
    "http://www.omg.org/XMI",
)

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


def get_xmi_attribute(element: ET.Element, local_name: str) -> Optional[str]:
    for namespace in XMI_NAMESPACES:
        value = element.get(f"{{{namespace}}}{local_name}")
        if value:
            return value
    return None


def get_xmi_id(element: ET.Element) -> Optional[str]:
    return get_xmi_attribute(element, "id")


def get_xmi_idref(element: ET.Element) -> Optional[str]:
    return get_xmi_attribute(element, "idref")


def get_xmi_type(element: ET.Element) -> Optional[str]:
    value = get_xmi_attribute(element, "type")
    if value:
        return value
    return element.get(XSI_TYPE)


class TransformationError(RuntimeError):
    """Raised when the transformation cannot be completed."""


def clean_whitespace(value: str) -> str:
    return WHITESPACE_RE.sub(" ", value).strip()


def strip_namespace(tag: str) -> str:
    if tag.startswith("{"):
        return tag.split("}", 1)[1]
    return tag


def extract_href(value: str) -> Optional[str]:
    match = re.search(r'href="([^"]+)"', value)
    if match:
        return html.unescape(match.group(1)).strip()
    return None


def _is_meaningful_href(value: str) -> bool:
    parsed = urlparse(value)
    if not parsed.scheme:
        return False
    if parsed.scheme in {"http", "https", "ftp"}:
        return bool(parsed.netloc)
    return bool(parsed.netloc or parsed.path)


def clean_htmlish(value: Optional[str]) -> str:
    if not value:
        return ""
    unescaped = html.unescape(value)
    href = extract_href(unescaped)
    if href and _is_meaningful_href(href):
        return href
    anchor_text = extract_anchor_text(unescaped)
    if anchor_text:
        return anchor_text
    text = HTML_TAG_RE.sub(" ", unescaped)
    return clean_whitespace(text)


def extract_anchor_text(value: str) -> Optional[str]:
    match = ANCHOR_TEXT_RE.search(value)
    if not match:
        return None
    text = HTML_TAG_RE.sub(" ", match.group(1))
    return clean_whitespace(text)


def normalize_primitive_name(name: Optional[str]) -> Optional[str]:
    if not name:
        return None
    return name.strip().lower()


def slugify(value: str) -> str:
    translated = translate_norwegian(value)
    normalized = unicodedata.normalize("NFKD", translated)
    ascii_value = normalized.encode("ascii", "ignore").decode("ascii")
    slug = re.sub(r"[^A-Za-z0-9]+", "_", ascii_value).strip("_")
    if not slug:
        raise TransformationError(f"Kan ikke lage nøkkel for navnet {value!r}")
    return slug.lower()


def format_begrepsreferanse(url: str) -> str:
    safe_url = html.escape(url, quote=True)
    return f'<a href="{safe_url}">Begrepsreferanse</a>'


def fetch_xmi_bytes(url: str, username: str, password: str) -> bytes:
    password_mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    password_mgr.add_password(None, url, username, password)
    handler = urllib.request.HTTPBasicAuthHandler(password_mgr)
    opener = urllib.request.build_opener(handler)
    with opener.open(url) as response:
        return response.read()


@dataclass
class TypeRef:
    category: str
    element_id: Optional[str] = None
    primitive_name: Optional[str] = None
    selection_kind: Optional[str] = None
    reference_path: Optional[str] = None


class XMIModel:
    """Convenience wrapper that indexes the XMI content."""

    def __init__(self, root: ET.Element) -> None:
        self.root = root
        self.elements_by_id: Dict[str, ET.Element] = {}
        self.element_type_by_id: Dict[str, str] = {}
        self.element_name_by_id: Dict[str, str] = {}
        self.element_package: Dict[str, Optional[str]] = {}
        self.package_parent: Dict[str, Optional[str]] = {}
        self.package_name_by_id: Dict[str, str] = {}
        self.comments_by_element: Dict[str, List[str]] = {}
        self.begreps_by_element: Dict[str, str] = {}
        self.elements_by_name: Dict[str, List[str]] = {}
        self.elements_by_concept: Dict[str, List[str]] = {}
        self.nullable_properties: Set[str] = set()
        self.code_metadata: Dict[str, Dict[str, str]] = {}
        self.restrictions: Dict[str, Dict[str, str]] = {}
        self.restriction_tag_keys: Dict[str, str] = {}
        self.root_classes: Dict[str, str] = {}
        self.losningsmodell_meta: Dict[str, Dict[str, Optional[str]]] = {}
        self.minst_en_classes: Set[str] = set()
        self.en_av_classes: Set[str] = set()
        self.selection_classes: Set[str] = set()
        self.realization_supplier: Dict[str, Dict[str, Optional[str]]] = {}
        self.generalizations: Dict[str, List[str]] = {}
        self.specializations: Dict[str, List[str]] = {}
        self._index_elements()
        self._assign_packages()
        self._collect_comments()
        self._collect_begrepsreferanse()
        self._collect_nullbar()
        self._collect_code_metadata()
        self._collect_restriction_tag_ids()
        self._collect_restrictions()
        self._collect_tagged_value_restrictions()
        self._collect_package_metadata()
        self._collect_root_classes()
        self._collect_selection_classes()
        self._collect_realizations()
        self._collect_generalizations()

    def _index_elements(self) -> None:
        for elem in self.root.iter():
            elem_id = get_xmi_id(elem)
            if not elem_id:
                continue
            self.elements_by_id[elem_id] = elem
            elem_type = get_xmi_type(elem)
            if elem_type:
                self.element_type_by_id[elem_id] = elem_type
            name = elem.get("name")
            if name:
                translated = translate_norwegian(name)
                self.element_name_by_id[elem_id] = translated
                self.elements_by_name.setdefault(translated, []).append(elem_id)

    def _assign_packages(self) -> None:
        def walk(node: ET.Element, current_package: Optional[str]) -> None:
            elem_id = get_xmi_id(node)
            tag = strip_namespace(node.tag)
            elem_type = get_xmi_type(node)
            new_package = current_package
            if (tag == "packagedElement" and elem_type == "uml:Package") or tag == "Package":
                pkg_id = elem_id
                self.package_parent[pkg_id] = current_package
                pkg_name = node.get("name") or pkg_id
                self.package_name_by_id[pkg_id] = pkg_name
                new_package = pkg_id
            if elem_id:
                self.element_package[elem_id] = new_package
            for child in list(node):
                walk(child, new_package)

        walk(self.root, None)

    def _collect_comments(self) -> None:
        for comment in self.root.findall(".//ownedComment"):
            body = comment.get("body")
            if not body:
                continue
            body_text = clean_whitespace(html.unescape(body))
            if not body_text:
                continue
            for target in comment.findall("annotatedElement"):
                element_id = get_xmi_idref(target)
                if not element_id:
                    href = target.get("href")
                    if href and "#" in href:
                        element_id = href.split("#")[-1]
                if element_id:
                    self.comments_by_element.setdefault(element_id, []).append(body_text)

    def _collect_begrepsreferanse(self) -> None:
        for node in self.root.findall(".//br:Modellelement", NS):
            target = (
                node.get("base_Property")
                or node.get("base_Class")
                or node.get("base_DataType")
                or node.get("base_PrimitiveType")
            )
            if not target:
                continue
            url = clean_htmlish(node.get("begrepsreferanse"))
            if url:
                self.begreps_by_element[target] = url
                self.elements_by_concept.setdefault(url, []).append(target)

    def _collect_nullbar(self) -> None:
        for node in self.root.findall(".//br:Nullbar", NS):
            base_property = node.get("base_Property")
            if base_property:
                self.nullable_properties.add(base_property)

    def _collect_code_metadata(self) -> None:
        for node in self.root.findall(".//br:Kode", NS):
            base = node.get("base_PrimitiveType")
            if not base:
                continue
            info: Dict[str, str] = {}
            kodeliste = clean_htmlish(node.get("kodelistereferanse"))
            if kodeliste:
                info["kodelistereferanse"] = kodeliste
            se_ogsa = clean_htmlish(node.get("seOgså"))
            if se_ogsa:
                info["seOgså"] = se_ogsa
            if info:
                self.code_metadata[base] = info



    def _collect_restriction_tag_ids(self) -> None:
        for node in self.root.findall(".//tag"):
            tag_id = node.get("tagID")
            name = node.get("name")
            if not tag_id or not name:
                continue
            parts = name.split(":")
            if len(parts) < 3:
                continue
            if parts[0] != "BRProfil" or not parts[1].startswith("Restriksjon"):
                continue
            self.restriction_tag_keys[tag_id] = parts[-1]

    def _collect_restrictions(self) -> None:
        for node in self.root.findall(".//br:Restriksjon", NS):
            target = (
                node.get("base_Property")
                or node.get("base_PrimitiveType")
                or node.get("base_DataType")
                or node.get("base_Class")
            )
            if not target:
                continue
            data: Dict[str, str] = self.restrictions.setdefault(target, {})
            for key, value in node.attrib.items():
                local_key = key.split("}", 1)[1] if key.startswith("{") else key
                if local_key.startswith("base_") or local_key in {"id"}:
                    continue
                data[local_key] = value




    def _collect_tagged_value_restrictions(self) -> None:
        if not self.restriction_tag_keys:
            return
        for element_id, element in self.elements_by_id.items():
            tagged_values = element.findall("taggedValue")
            if not tagged_values:
                continue
            for tagged in tagged_values:
                tag_def = tagged.find("tagDefinition")
                if tag_def is None:
                    continue
                href = tag_def.get("href")
                if not href:
                    continue
                tag_id = href.split("#")[-1] if "#" in href else href
                key = self.restriction_tag_keys.get(tag_id)
                if not key:
                    continue
                value = self._extract_tagged_value(tagged)
                if value is None:
                    continue
                data = self.restrictions.setdefault(element_id, {})
                data[key] = value

    def _extract_tagged_value(self, node: ET.Element) -> Optional[str]:
        value_node = node.find("value")
        if value_node is not None:
            text_value = value_node.text
            if text_value:
                return text_value.strip()
        attr_value = node.get("value")
        if attr_value:
            return attr_value.strip()
        return None

    def _collect_package_metadata(self) -> None:
        for node in self.root.findall(".//br:Løsningsmodell", NS):
            package_id = node.get("base_Package")
            if not package_id:
                continue
            navnerom = clean_htmlish(node.get("navnerom"))
            status = clean_htmlish(node.get("status"))
            versjon = clean_htmlish(node.get("versjon"))
            begreps_node = node.find("begrepsreferanse")
            begreps = clean_htmlish(begreps_node.text if begreps_node is not None else None)
            description = clean_whitespace(" ".join(self.comments_by_element.get(package_id, [])))
            self.losningsmodell_meta[package_id] = {
                "navnerom": navnerom or None,
                "status": status or None,
                "versjon": versjon or None,
                "begrepsreferanse": begreps or None,
                "beskrivelse": description or None,
            }

    def _collect_root_classes(self) -> None:
        for node in self.root.findall(".//br:Rotelement", NS):
            class_id = node.get("base_Class")
            if not class_id:
                continue
            package_id = self.element_package.get(class_id)
            if package_id and package_id not in self.root_classes:
                self.root_classes[package_id] = class_id

    def _collect_selection_classes(self) -> None:
        for node in self.root.findall(".//br:MinstEn", NS):
            base = node.get("base_Class")
            if base:
                self.minst_en_classes.add(base)
        for node in self.root.findall(".//br:EnAv", NS):
            base = node.get("base_Class")
            if base:
                self.en_av_classes.add(base)
        self.selection_classes = self.minst_en_classes | self.en_av_classes

    def _collect_realizations(self) -> None:
        for rel in self.root.findall(".//packagedElement[@xmi:type='uml:Realization']", NS):
            client = rel.find("client")
            supplier = rel.find("supplier")
            client_id = self._resolve_ref(client)
            if not client_id:
                continue
            supplier_id = self._resolve_ref(supplier)
            referent_path = None
            if supplier is not None:
                ref_ext = supplier.find(".//referenceExtension")
                if ref_ext is not None:
                    referent_path = ref_ext.get("referentPath")
            self.realization_supplier[client_id] = {
                "supplier_id": supplier_id,
                "referent_path": referent_path,
            }

    def _collect_generalizations(self) -> None:
        for elem_id, elem in self.elements_by_id.items():
            elem_type = self.element_type_by_id.get(elem_id)
            if elem_type not in {"uml:Class", "uml:DataType"}:
                continue
            supers: List[str] = []
            for gen in elem.findall("generalization"):
                general = gen.get("general")
                if general:
                    supers.append(general)
            if supers:
                self.generalizations[elem_id] = supers
                for super_id in supers:
                    self.specializations.setdefault(super_id, []).append(elem_id)

    def _resolve_ref(self, node: Optional[ET.Element]) -> Optional[str]:
        if node is None:
            return None
        ref = get_xmi_idref(node)
        if ref:
            return ref
        href = node.get("href")
        if href and "#" in href:
            return href.split("#")[-1]
        return None

    def get_documentation(self, element_id: str) -> str:
        texts = self.comments_by_element.get(element_id, [])
        return clean_whitespace(" ".join(texts)) if texts else ""

    def get_begrepsreferanse(self, element_id: str) -> Optional[str]:
        return self.begreps_by_element.get(element_id)

    def elements_with_concept(self, concept: Optional[str]) -> List[str]:
        if not concept:
            return []
        return list(self.elements_by_concept.get(concept, []))

    def alternatives_with_same_name(self, element_id: Optional[str]) -> List[str]:
        if not element_id:
            return []
        name = self.element_name_by_id.get(element_id)
        if not name:
            return []
        return [alt for alt in self.elements_by_name.get(name, []) if alt != element_id]

    def get_package_metadata(self, package_id: str) -> Dict[str, Optional[str]]:
        return self.losningsmodell_meta.get(package_id, {})

    def get_root_class(self, package_id: str) -> Optional[str]:
        return self.root_classes.get(package_id)

    def iter_solution_packages(self) -> Iterator[str]:
        return iter(self.losningsmodell_meta.keys())

    def descends_from_package(self, element_id: str, package_id: str) -> bool:
        current = self.element_package.get(element_id)
        while current is not None:
            if current == package_id:
                return True
            current = self.package_parent.get(current)
        return False

    def get_specializations(self, element_id: Optional[str]) -> List[str]:
        if not element_id:
            return []
        seen: Set[str] = set()
        ordered: List[str] = []
        stack = list(self.specializations.get(element_id, []))
        while stack:
            candidate = stack.pop()
            if candidate in seen:
                continue
            seen.add(candidate)
            ordered.append(candidate)
            stack.extend(self.specializations.get(candidate, []))
        return ordered

    def get_class_attributes(self, class_id: str) -> List[ET.Element]:
        element = self.elements_by_id.get(class_id)
        if element is None:
            return []
        return element.findall("ownedAttribute")

    def classes_in_package(self, package_id: str) -> List[str]:
        return [
            elem_id
            for elem_id, elem_type in self.element_type_by_id.items()
            if elem_type == "uml:Class" and self.descends_from_package(elem_id, package_id)
        ]

    def is_nullable(self, element_id: Optional[str]) -> bool:
        return bool(element_id) and element_id in self.nullable_properties

    def get_restrictions(self, element_id: Optional[str]) -> Dict[str, str]:
        if not element_id:
            return {}
        return self.restrictions.get(element_id, {})

    def get_code_info(self, element_id: Optional[str]) -> Dict[str, str]:
        if not element_id:
            return {}
        return self.code_metadata.get(element_id, {})

    def get_realization_base_name(self, element_id: str) -> Optional[str]:
        info = self.realization_supplier.get(element_id)
        if not info:
            return None
        referent_path = info.get("referent_path")
        if referent_path:
            return referent_path.split("::")[-1]
        supplier_id = info.get("supplier_id")
        if supplier_id:
            return self.element_name_by_id.get(supplier_id)
        return None

    def get_multiplicity(self, prop: ET.Element) -> Tuple[int, Optional[int]]:
        lower_text = self._find_multiplicity_value(prop, "lowerValue")
        upper_text = self._find_multiplicity_value(prop, "upperValue")
        lower = int(lower_text) if lower_text else 1
        if upper_text == "*" or upper_text is None:
            upper = None
        else:
            upper = int(upper_text)
        return lower, upper

    def _find_multiplicity_value(self, prop: ET.Element, name: str) -> Optional[str]:
        for node in prop.iter():
            if strip_namespace(node.tag) == name:
                value = node.get("value")
                if value is not None:
                    return value
        return None

    def resolve_type(self, prop: ET.Element) -> TypeRef:
        prop_type = prop.get("type")
        href_id = None
        reference_path: Optional[str] = None
        type_node = prop.find("type")
        if type_node is not None:
            href = type_node.get("href")
            if href and "#" in href:
                href_id = href.split("#")[-1]
            ref_ext = type_node.find(".//referenceExtension")
            if ref_ext is not None:
                reference_path = ref_ext.get("referentPath")
        target_id = prop_type or href_id
        if target_id and target_id in self.selection_classes:
            selection_kind = "minst_en" if target_id in self.minst_en_classes else "en_av"
            return TypeRef("selection", element_id=target_id, selection_kind=selection_kind)
        if target_id and target_id in self.elements_by_id:
            elem_type = self.element_type_by_id.get(target_id)
            if elem_type == "uml:Class":
                return TypeRef("class", element_id=target_id)
            if elem_type == "uml:DataType":
                return TypeRef("datatype", element_id=target_id)
            if elem_type == "uml:Enumeration":
                return TypeRef("enumeration", element_id=target_id)
            if elem_type == "uml:PrimitiveType":
                name = normalize_primitive_name(self.element_name_by_id.get(target_id))
                if name in PRIMITIVE_TYPE_MAP:
                    return TypeRef("primitive", element_id=target_id, primitive_name=name)
                return TypeRef("simple", element_id=target_id)
        primitive_name = normalize_primitive_name(reference_path.split("::")[-1] if reference_path else None)
        if primitive_name in PRIMITIVE_TYPE_MAP:
            return TypeRef("primitive", primitive_name=primitive_name, reference_path=reference_path)
        raise TransformationError(f"Fant ikke typen for egenskapen '{prop.get('name')}'")


class JsonSchemaBuilder:
    def __init__(self, model: XMIModel, package_id: str) -> None:
        self.model = model
        self.package_id = package_id
        self.package_name = model.package_name_by_id.get(package_id, package_id)
        self.definitions: Dict[str, Dict[str, Any]] = {}
        self.definition_name_by_id: Dict[str, str] = {}
        self.used_definition_names: Set[str] = set()

    def build(self) -> Dict[str, Any]:
        package_meta = self.model.get_package_metadata(self.package_id)
        root_class_id = self.model.get_root_class(self.package_id)
        primary_required = True
        root_candidates: List[str]
        if root_class_id:
            root_candidates = [root_class_id]
        else:
            fallback_classes = self.model.classes_in_package(self.package_id)
            if not fallback_classes:
                raise TransformationError(
                    f"Fant ikke rotelement for løsningsmodellen '{self.package_name}'"
                )
            primary_required = False
            root_candidates = fallback_classes
            print(
                f"Advarsel: løsningsmodellen '{self.package_name}' mangler Rotelement, oppretter schema med {len(root_candidates)} rotobjekter.",
                file=sys.stderr,
            )
        root_entries = [(class_id, self.ensure_definition(class_id)) for class_id in root_candidates]
        schema = self._build_root_schema(package_meta, root_entries, primary_required)
        if self.definitions:
            schema["definitions"] = self.definitions
        return schema

    def _build_root_schema(
        self,
        package_meta: Dict[str, Optional[str]],
        root_entries: Sequence[Tuple[str, str]],
        require_primary: bool,
    ) -> Dict[str, Any]:
        navnerom = package_meta.get("navnerom")
        versjon = package_meta.get("versjon")
        status = package_meta.get("status")
        beskrivelse = package_meta.get("beskrivelse")
        begrep = package_meta.get("begrepsreferanse")
        metadata: Dict[str, Optional[str]] = {
            "identifikatorForSkjema": navnerom or "",
            "versjonsnummerForSkjema": versjon or "",
        }
        if status:
            metadata["statusForSkjema"] = status
        if beskrivelse:
            metadata["beskrivelseForSkjema"] = beskrivelse
        if begrep:
            metadata["begrepsreferanse"] = begrep
        properties: Dict[str, Any] = {
            "identifikatorForSkjema": {
                "type": "string",
                "description": "Navnerom/identifikator til skjemaet",
            },
            "versjonsnummerForSkjema": {
                "type": "string",
                "description": "Versjonsnummeret til skjemaet",
            },
        }
        required: List[str] = []
        taken_names = set(properties.keys())
        for idx, (class_id, def_name) in enumerate(root_entries):
            class_name = self.model.element_name_by_id.get(class_id, class_id)
            prop_name = self._derive_root_property_name(class_name or f"element{idx+1}", taken_names)
            properties[prop_name] = {"$ref": f"#/definitions/{def_name}"}
            taken_names.add(prop_name)
            if require_primary and idx == 0:
                required.append(prop_name)
        schema: Dict[str, Any] = {
            "$schema": "http://json-schema.org/draft-06/schema#",
            "$id": navnerom or "",
            "type": "object",
            "additionalProperties": False,
            "title": self.package_name,
            "description": json.dumps(metadata, ensure_ascii=False),
            "properties": properties,
            "required": required,
        }
        if status:
            schema["properties"]["statusForSkjema"] = {
                "type": "string",
                "description": "Status for skjemaet",
            }
        if begrep:
            schema["x-skos-concept"] = begrep
        return schema

    def _derive_root_property_name(self, raw_name: str, taken: Set[str]) -> str:
        base = raw_name[:1].lower() + raw_name[1:] if raw_name else "rotObjekt"
        if not base:
            base = "rotObjekt"
        candidate = base
        suffix = 2
        while candidate in taken:
            candidate = f"{base}_{suffix}"
            suffix += 1
        return candidate

    def ensure_definition(self, element_id: str) -> str:
        if element_id in self.definition_name_by_id:
            return self.definition_name_by_id[element_id]
        if element_id in self.model.selection_classes:
            raise TransformationError("Valgklasser skal ikke eksporteres direkte som definisjoner.")
        raw_name = self.model.element_name_by_id.get(element_id, element_id)
        def_name = self._unique_definition_name(raw_name or slugify(element_id))
        self.definition_name_by_id[element_id] = def_name
        placeholder: Dict[str, Any] = {}
        self.definitions[def_name] = placeholder
        elem_type = self.model.element_type_by_id.get(element_id)
        if elem_type in {"uml:Class", "uml:DataType"}:
            schema = self._build_object_definition(element_id)
        elif elem_type == "uml:Enumeration":
            schema = self._build_enumeration_definition(element_id)
        elif elem_type == "uml:PrimitiveType":
            schema = self._build_simple_type_definition(element_id)
        else:
            raise TransformationError(f"Støtter ikke elementtypen {elem_type!r}")
        self.definitions[def_name] = schema
        return def_name

    def _unique_definition_name(self, name: str) -> str:
        candidate = name
        suffix = 2
        while candidate in self.used_definition_names:
            candidate = f"{name}_{suffix}"
            suffix += 1
        self.used_definition_names.add(candidate)
        return candidate

    def _build_object_definition(self, element_id: str) -> Dict[str, Any]:
        element_name = self.model.element_name_by_id.get(element_id, element_id)
        properties: Dict[str, Any] = {}
        required: List[str] = []
        any_of_blocks: List[Dict[str, Any]] = []
        one_of_blocks: List[Dict[str, Any]] = []
        for attr in self.model.get_class_attributes(element_id):
            attr_id = get_xmi_id(attr)
            attr_name = attr.get("name")
            try:
                type_ref = self.model.resolve_type(attr)
            except TransformationError as exc:
                print(
                    f"Advarsel: hopper over egenskap '{attr_name}' ({exc})",
                    file=sys.stderr,
                )
                continue
            if type_ref.category == "selection" and type_ref.element_id:
                blocks, selection_props = self._build_selection_blocks(type_ref.element_id)
                for prop_name, schema in selection_props.items():
                    properties.setdefault(prop_name, schema)
                if type_ref.selection_kind == "minst_en":
                    any_of_blocks.extend(blocks)
                else:
                    one_of_blocks.extend(blocks)
                continue
            if not attr_name:
                continue
            attr_name = translate_norwegian(attr_name)
            schema = self._build_property_schema(attr, type_ref)
            properties[attr_name] = schema
            lower, _ = self.model.get_multiplicity(attr)
            if lower >= 1 and attr_id not in self.model.selection_classes:
                required.append(attr_name)
        description, concept = self._compose_description_and_concept(element_id)
        object_schema: Dict[str, Any] = {
            "type": "object",
            "properties": properties,
            "additionalProperties": False,
        }
        if description:
            object_schema["description"] = description
        if concept:
            object_schema["x-skos-concept"] = concept
        if required:
            object_schema["required"] = required
        if any_of_blocks:
            object_schema["anyOf"] = any_of_blocks
        if one_of_blocks:
            object_schema["oneOf"] = one_of_blocks
        supers = self.model.generalizations.get(element_id, [])
        if supers:
            all_of: List[Dict[str, Any]] = []
            for super_id in supers:
                super_def = self.ensure_definition(super_id)
                all_of.append({"$ref": f"#/definitions/{super_def}"})
            all_of.append(object_schema)
            result: Dict[str, Any] = {"title": element_name, "allOf": all_of}
            if concept:
                result["x-skos-concept"] = concept
            return result
        return {"title": element_name, **object_schema}

    def _build_selection_blocks(
        self, selection_class_id: str
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Dict[str, Any]]]:
        blocks: List[Dict[str, Any]] = []
        property_schemas: Dict[str, Dict[str, Any]] = {}
        for attr in self.model.get_class_attributes(selection_class_id):
            attr_name = attr.get("name")
            if not attr_name:
                continue
            attr_name = translate_norwegian(attr_name)
            try:
                type_ref = self.model.resolve_type(attr)
            except TransformationError as exc:
                print(
                    f"Advarsel: hopper over valg-egenskap '{attr_name}' ({exc})",
                    file=sys.stderr,
                )
                continue
            schema = self._build_property_schema(attr, type_ref)
            property_schemas[attr_name] = schema
            blocks.append({"properties": {attr_name: copy.deepcopy(schema)}, "required": [attr_name]})
        return blocks, property_schemas

    def _build_enumeration_definition(self, element_id: str) -> Dict[str, Any]:
        element = self.model.elements_by_id[element_id]
        values = []
        for literal in element.findall("ownedLiteral"):
            name = literal.get("name")
            if name:
                values.append(translate_norwegian(name))
        schema: Dict[str, Any] = {
            "title": self.model.element_name_by_id.get(element_id, element_id),
            "type": "string",
            "enum": values,
        }
        description, concept = self._compose_description_and_concept(element_id)
        if description:
            schema["description"] = description
        if concept:
            schema["x-skos-concept"] = concept
        return schema

    def _build_simple_type_definition(self, element_id: str) -> Dict[str, Any]:
        base_name = self.model.get_realization_base_name(element_id)
        primitive_schema = self._schema_for_primitive(base_name)
        schema = copy.deepcopy(primitive_schema)
        description, concept = self._compose_description_and_concept(element_id)
        code_info = self.model.get_code_info(element_id)
        if code_info.get("kodelistereferanse"):
            link = html.escape(code_info["kodelistereferanse"], quote=True)
            description = (description + " ").strip() + f'(<a href="{link}">Kodelistereferanse</a>)'
        if code_info.get("seOgså"):
            link = html.escape(code_info["seOgså"], quote=True)
            description = (description + " ").strip() + f'(<a href="{link}">seOgså</a>)'
        if description:
            schema["description"] = description
        if concept:
            schema["x-skos-concept"] = concept
        kodeliste = code_info.get("kodelistereferanse")
        see_also = code_info.get("seOgså")
        if kodeliste:
            schema["x-ogc-codelisturi"] = kodeliste
        if see_also:
            schema["x-rdfs-seeAlso"] = see_also
        restrictions = self.model.get_restrictions(element_id)
        if restrictions:
            self._apply_restrictions(schema, restrictions)
        schema["title"] = self.model.element_name_by_id.get(element_id, element_id)
        return schema

    def _compose_description_and_concept(self, element_id: str) -> Tuple[str, Optional[str]]:
        parts: List[str] = []
        documentation = self.model.get_documentation(element_id)
        concept = self.model.get_begrepsreferanse(element_id)
        if not documentation or not concept:
            for alt_id in self.model.alternatives_with_same_name(element_id):
                if not documentation:
                    alt_doc = self.model.get_documentation(alt_id)
                    if alt_doc:
                        documentation = alt_doc
                if not concept:
                    alt_concept = self.model.get_begrepsreferanse(alt_id)
                    if alt_concept:
                        concept = alt_concept
                if documentation and concept:
                    break
        if documentation:
            parts.append(documentation)
        if concept:
            parts.append(format_begrepsreferanse(concept))
        return " ".join(parts).strip(), concept

    def _build_property_schema(self, prop: ET.Element, type_ref: TypeRef) -> Dict[str, Any]:
        schema = self._schema_for_type(type_ref)
        prop_id = get_xmi_id(prop)
        restrictions = self.model.get_restrictions(prop_id)
        if restrictions:
            self._apply_restrictions(schema, restrictions)
        lower, upper = self.model.get_multiplicity(prop)
        is_array = lower > 1 or (upper is not None and upper > 1) or upper is None
        if is_array:
            array_schema: Dict[str, Any] = {"type": "array", "items": schema}
            if lower > 0:
                array_schema["minItems"] = lower
            if upper is not None:
                array_schema["maxItems"] = upper
            schema = array_schema
        description, concept = self._compose_description_and_concept(prop_id or "")
        if description:
            schema["description"] = description
        if concept:
            schema["x-skos-concept"] = concept
        if self.model.is_nullable(prop_id):
            schema = self._wrap_nullable(schema)
        return schema

    def _wrap_nullable(self, schema: Dict[str, Any]) -> Dict[str, Any]:
        if "$ref" in schema or schema.get("type") == "array" or "items" in schema:
            return {"oneOf": [{"type": "null"}, schema]}
        schema_type = schema.get("type")
        if isinstance(schema_type, list):
            if "null" not in schema_type:
                schema_type.append("null")
            return schema
        if isinstance(schema_type, str):
            schema["type"] = [schema_type, "null"]
            return schema
        return {"oneOf": [{"type": "null"}, schema]}

    def _schema_for_type(self, type_ref: TypeRef) -> Dict[str, Any]:
        if type_ref.category == "primitive":
            return copy.deepcopy(self._schema_for_primitive(type_ref.primitive_name))
        if type_ref.category in {"class", "datatype", "enumeration", "simple"}:
            if not type_ref.element_id:
                raise TransformationError("Ufullstendig typeinformasjon")
            def_name = self.ensure_definition(type_ref.element_id)
            schema: Dict[str, Any] = {"$ref": f"#/definitions/{def_name}"}
            if type_ref.category in {"class", "datatype"}:
                specializations = self.model.get_specializations(type_ref.element_id)
                if specializations:
                    variants = [schema]
                    for spec_id in specializations:
                        spec_def = self.ensure_definition(spec_id)
                        variants.append({"$ref": f"#/definitions/{spec_def}"})
                    return {"oneOf": variants}
            return schema
        raise TransformationError(f"Støtter ikke typekategorien {type_ref.category}")

    def _schema_for_primitive(self, name: Optional[str]) -> Dict[str, Any]:
        primitive_name = normalize_primitive_name(name)
        if not primitive_name:
            print(
                f"Advarsel: mangler primitivtype for '{name}', antar string",
                file=sys.stderr,
            )
            primitive_name = "string"
        if primitive_name not in PRIMITIVE_TYPE_MAP:
            raise TransformationError(f"Ukjent primitivtype {name!r}")
        return PRIMITIVE_TYPE_MAP[primitive_name]

    def _apply_restrictions(self, schema: Dict[str, Any], restrictions: Dict[str, str]) -> None:
        target = schema
        if schema.get("type") == "array" and "items" in schema:
            target = schema["items"]
        if "$ref" in target:
            return
        for key, value in restrictions.items():
            if key == "mønster":
                target["pattern"] = value
            elif key == "minimumInklusivt":
                target["minimum"] = self._parse_number(value)
            elif key == "maksimumInklusivt":
                target["maximum"] = self._parse_number(value)
            elif key == "minimumIkkeInklusivt":
                target["exclusiveMinimum"] = self._parse_number(value)
            elif key == "maksimumIkkeInklusivt":
                target["exclusiveMaximum"] = self._parse_number(value)
            elif key == "maksLengde":
                target["maxLength"] = int(value)
            elif key == "minimumLengde":
                target["minLength"] = int(value)
            elif key == "lengde":
                length = int(value)
                target["minLength"] = length
                target["maxLength"] = length

    def _parse_number(self, value: str) -> float:
        try:
            return int(value)
        except ValueError:
            return float(value)


def parse_arguments(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Generate JSON Schema files from SOSI Løsningsmodell packages contained in an XMI file."
        )
    )
    parser.add_argument("--url", help="URL til XMI-modellen (brukes dersom --xmi ikke er satt).")
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
    parser.add_argument("--xmi", type=Path, help="Les XMI fra lokal fil i stedet for å laste ned.")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("jsonschemas"),
        help="Mappe hvor JSON Schema-filene skal lagres (standard: jsonschemas).",
    )
    parser.add_argument(
        "--package",
        action="append",
        help="Navn på løsningsmodell som skal genereres (kan angis flere ganger).",
    )
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_arguments(argv)
    if not args.xmi and not args.url:
        raise TransformationError("Oppgi enten --xmi eller --url for å hente XMI-modellen.")
    if args.xmi:
        data = args.xmi.read_bytes()
    else:
        data = fetch_xmi_bytes(args.url, args.username, args.password)
    root = ET.fromstring(data)
    model = XMIModel(root)
    target_packages = list(model.iter_solution_packages())
    if args.package:
        selected = set(name.lower() for name in args.package)
        target_packages = [
            pkg for pkg in target_packages if model.package_name_by_id.get(pkg, pkg).lower() in selected
        ]
    if not target_packages:
        raise TransformationError("Fant ingen løsningsmodeller i XMI-filen.")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for package_id in target_packages:
        builder = JsonSchemaBuilder(model, package_id)
        try:
            schema = builder.build()
        except TransformationError as exc:
            package_name = model.package_name_by_id.get(package_id, package_id)
            print(
                f"Advarsel: hopper over løsningsmodellen '{package_name}' ({exc})",
                file=sys.stderr,
            )
            continue
        file_name = f"{slugify(model.package_name_by_id.get(package_id, package_id))}.schema.json"
        output_path = args.output_dir / file_name
        output_path.write_text(json.dumps(schema, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"Skrev {output_path}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except TransformationError as exc:
        print(f"Feil under transformasjon: {exc}", file=sys.stderr)
        sys.exit(1)
