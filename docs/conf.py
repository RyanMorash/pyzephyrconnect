"""Sphinx configuration for the pyzephyrconnect documentation."""

from __future__ import annotations

import sys
from pathlib import Path

# Editable installs already expose the package, but a bare ``sphinx-build``
# from a checkout should still import the tree under src/. Autodoc imports
# the real modules, so the docs extra has to be installed too: auth pulls
# in aiohttp, boto3, and pycognito at import time.
_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "src"))

import pyzephyrconnect  # noqa: E402

project = "pyzephyrconnect"
author = "Ryan Morash"
copyright = "2026, Ryan Morash"
version = pyzephyrconnect.__version__
release = pyzephyrconnect.__version__

extensions = [
    "myst_parser",
    "sphinx.ext.autodoc",
    "sphinx.ext.intersphinx",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
]

# Docstrings use single backticks for code, matching the rest of the repo.
# Left as the default role, each one becomes a cross-reference and the
# build warns on names that are not objects.
default_role = "literal"

# Missing targets are warnings. Read the Docs runs with fail_on_warning,
# and CI passes -W, so a broken reference fails both builds. Unqualified
# names are ignored below: Napoleon emits them from Raises/Args lines
# written as short names (``ZephyrAuthError``) or annotation expressions
# (``list[Hood]``). Narrative pages use qualified names, which still have
# to resolve.
nitpicky = True
nitpick_ignore_regex = [
    (r"py:.*", r"^[^.]+$"),
    (r"py:.*", r".*[\[\]|].*"),
]

# Google-style docstrings, the convention ruff's D rules enforce.
napoleon_google_docstring = True
napoleon_numpy_docstring = False
napoleon_attr_annotations = True
napoleon_preprocess_types = False

autodoc_member_order = "bysource"
autodoc_typehints = "signature"
autodoc_typehints_format = "short"
autoclass_content = "class"
# Document ``__init__`` as its own method instead of splicing its
# parameters onto the class line. Hood still excludes that method; its
# constructor is internal wiring. See docs/api/hood.rst.
autodoc_class_signature = "separated"
# Keep defaults as written (``DEFAULT_ENDPOINTS``) rather than the repr
# of the evaluated object.
autodoc_preserve_defaults = True

intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
    "aiohttp": ("https://docs.aiohttp.org/en/stable/", None),
}
intersphinx_timeout = 10

# PROTOCOL.md and VALIDATION.md are included from the repository root.
# Anchors make section links stable on Read the Docs.
myst_heading_anchors = 3

exclude_patterns = ["_build", "api-notes.md"]

html_theme = "sphinx_rtd_theme"
html_theme_options = {
    "navigation_depth": 3,
    "style_external_links": True,
}
html_context = {
    "display_github": True,
    "github_user": "RyanMorash",
    "github_repo": "pyzephyrconnect",
    "github_version": "main",
    "conf_py_path": "/docs/",
}
html_title = "pyzephyrconnect"
html_show_sphinx = False


def setup(app):
    """Register the intersphinx alias used by annotated signatures."""
    app.connect("missing-reference", _alias_intersphinx_target)


def _alias_intersphinx_target(app, env, node, contnode):
    """Point ``aiohttp.client.ClientSession`` at the published target.

    ``ClientSession.__module__`` is ``aiohttp.client``, so autodoc links
    that. The aiohttp inventory publishes the re-export,
    ``aiohttp.ClientSession``, and the module path is not a target.
    """
    if node.get("reftarget") != "aiohttp.client.ClientSession":
        return None
    from sphinx.ext.intersphinx import missing_reference

    alias = node.deepcopy()
    alias["reftarget"] = "aiohttp.ClientSession"
    return missing_reference(app, env, alias, contnode)
