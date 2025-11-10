# XMI transformers

This repository exposes a reusable GitHub Action and companion CLI scripts for
turning XMI modeller into either

* Kartverket - pygeoapi `resources` YAML (`transform_xmi_to_pygeoapiconfig.py`)
* Brreg - JSON Schema-filer (`transform_xmi_to_jsonschema.py`)

Both transformers share the same authentication/downloading logic so you can run
them locally or inside CI via the provided GitHub Action.

## Usage

### GitHub Actions

#### Pygeoapi config

```yaml
name: Generate pygeoapi config

on:
  workflow_dispatch:
    inputs:
      xmi_url:
        description: URL to the SOSI XMI
        required: true

jobs:
  build-config:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout calling repo
        uses: actions/checkout@v4

      - name: Generate pygeoapi YAML
        uses: arkitektum/xmitransforms@main
        with:
          url: ${{ github.event.inputs.xmi_url }}
          output: configs/admenheter.yaml
```

Inputs for `arkitektum/xmitransforms@main`:

| Input              | Required | Default | Description |
| ------------------ | -------- | ------- | ----------- |
| `url`              | No       | —       | Remote URL for the XMI model (use when you do not provide `xmi`). |
| `xmi`              | No       | —       | Path to a local XMI file already available in the workflow workspace. |
| `output`           | No       | —       | Output YAML path (default: `<xmi file>.yaml`). |
| `username`         | No       | `sosi`  | Username for HTTP basic authentication. |
| `password`         | No       | `sosi`  | Password for HTTP basic authentication. |
| `working-directory`| No       | `.`     | Working directory for the command invocation. |

#### JSON Schema

```yaml
name: Generate JSON Schema from XMI

on:
  workflow_dispatch:
    inputs:
      xmi_url:
        description: URL to the XMI
        required: true

jobs:
  build-schema:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Generate JSON Schemas
        uses: arkitektum/xmitransforms/jsonschema@main
        with:
          url: ${{ github.event.inputs.xmi_url }}
          jsonschema-output-dir: schemas
          jsonschema-packages: |
            Løsningsmodellnavn
            EksempelMedVerdirestriksjoner
```

Inputs for `arkitektum/xmitransforms/jsonschema@main`:

| Input                   | Required | Default       | Description |
| ----------------------- | -------- | ------------- | ----------- |
| `url`                   | No       | —             | Remote URL for the XMI model (use when you do not provide `xmi`). |
| `xmi`                   | No       | —             | Path to a local XMI file already available in the workflow workspace. |
| `jsonschema-output-dir` | No       | `jsonschemas` | Directory where JSON Schema files will be written. |
| `jsonschema-packages`   | No       | —             | Optional newline-separated list of package names to limit JSON Schema generation. |
| `username`              | No       | `sosi`        | Username for HTTP basic authentication. |
| `password`              | No       | `sosi`        | Password for HTTP basic authentication. |
| `working-directory`     | No       | `.`           | Working directory for the command invocation. |

Either `url` or `xmi` must be provided. The generated YAML file is placed in the
specified `output` location (or derived automatically from the XMI file name).

## Local development

You can still run the transformers locally:

```bash
python transform_xmi_to_pygeoapiconfig.py --xmi AdministrativeEnheter_FylkerOgKommuner-20240101.xml --output admenheter.yaml
```

or download directly from SOSI:

```bash
python transform_xmi_to_pygeoapiconfig.py \
  --url "https://sosi.geonorge.no/svn/SOSI/SOSI Del 3/Statens kartverk/AdministrativeEnheter_FylkerOgKommuner-20240101.xml" \
  --output admenheter.yaml
```

### JSON Schema transformer locally

```bash
python transform_xmi_to_jsonschema.py --xmi tests/data/Løsningsmodelleksempel.xml --output-dir jsonschemas
```

Limit output to specific løsningsmodeller:

```bash
python transform_xmi_to_jsonschema.py \
  --xmi tests/data/Løsningsmodelleksempel.xml \
  --output-dir jsonschemas \
  --package Løsningsmodellnavn \
  --package EksempelMedVerdirestriksjoner
```
