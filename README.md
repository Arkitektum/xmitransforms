# pygeoapi configuration transformer

This repository exposes a reusable GitHub Action that transforms a SOSI XMI model
into a pygeoapi `resources` YAML file by reusing the logic in
`transform_xmi_to_pygeoapiconfig.py`.

## Usage

Create a workflow in another repository and reference this action:

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
        uses: arkitektum/pygeoapiconfig@main
        with:
          url: ${{ github.event.inputs.xmi_url }}
          output: configs/admenheter.yaml
```

### Inputs

| Input              | Required | Default | Description                                                  |
| ------------------ | -------- | ------- | ------------------------------------------------------------ |
| `url`              | No       | —       | Remote URL for the XMI model (use when you do not provide `xmi`). |
| `xmi`              | No       | —       | Path to a local XMI file already available in the workflow workspace. |
| `output`           | No       | —       | Output YAML path (default: `<xmi file>.yaml`).               |
| `username`         | No       | `sosi`  | Username for HTTP basic authentication.                      |
| `password`         | No       | `sosi`  | Password for HTTP basic authentication.                      |
| `working-directory`| No       | `.`     | Working directory for the command invocation.                |

Either `url` or `xmi` must be provided. The generated YAML file is placed in the
specified `output` location (or derived automatically from the XMI file name).

## Local development

You can still run the transformer locally:

```bash
python transform_xmi_to_pygeoapiconfig.py --xmi AdministrativeEnheter_FylkerOgKommuner-20240101.xml --output admenheter.yaml
```

or download directly from SOSI:

```bash
python transform_xmi_to_pygeoapiconfig.py \
  --url "https://sosi.geonorge.no/svn/SOSI/SOSI Del 3/Statens kartverk/AdministrativeEnheter_FylkerOgKommuner-20240101.xml" \
  --output admenheter.yaml
```
