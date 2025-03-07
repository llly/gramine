# pylint: skip-file
#
# Configuration file for the Sphinx documentation builder.
#
# This file does only contain a selection of the most common options. For a
# full list see the documentation:
# http://www.sphinx-doc.org/en/master/config

# -- Path setup --------------------------------------------------------------

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.

import os
import sys
sys.path.insert(0, os.path.abspath('../python'))
os.environ['GRAMINE_IMPORT_FOR_SPHINX_ANYWAY'] = '1'

import pathlib
import subprocess

# -- Project information -----------------------------------------------------

project = 'Gramine'
copyright = '2022, Gramine Contributors'
author = 'Gramine Contributors'

# The short X.Y version
version = ''
# The full version, including alpha/beta/rc tags
release = ''


# -- General configuration ---------------------------------------------------

# If your documentation needs a minimal Sphinx version, state it here.
#
# needs_sphinx = '1.0'

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.intersphinx',
    'sphinx.ext.napoleon',
    'sphinx.ext.todo',
    'sphinx_rtd_theme',
]

# Add any paths that contain templates here, relative to this directory.
templates_path = ['_templates']

# The suffix(es) of source filenames.
source_suffix = {
    '.rst': 'restructuredtext',
}

# The master toctree document.
master_doc = 'index'

# The language for content autogenerated by Sphinx. Refer to documentation
# for a list of supported languages.
#
# This is also used if you do content translation via gettext catalogs.
# Usually you set "language" from the command line for these cases.
language = None

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']

# The name of the Pygments (syntax highlighting) style to use.
pygments_style = None

highlight_language = 'c'
primary_domain = 'c'

rst_stable_checkout = '\\'
if 'READTHEDOCS' in os.environ:
    rtd_current_version = os.environ['READTHEDOCS_VERSION']

    if rtd_current_version.startswith('v'):
        rst_stable_checkout = rtd_current_version

    elif rtd_current_version == 'stable':
        # we don't have a version, we may be able to check from git
        try:
            tags = [tag for tag in subprocess.check_output(
                    ['git', 'tag', '--points-at']).decode().strip().split()
                if tag.startswith('v')]
            rst_stable_checkout = tags.pop()
        except (subprocess.CalledProcessError, IndexError):
            pass

rst_prolog = f'''
.. |~| unicode:: 0xa0
   :trim:

.. |stable-checkout| replace:: {rst_stable_checkout}
'''

breathe_projects = {p: '_build/doxygen-{}/xml'.format(p)
    for p in ('libos', 'pal', 'pal-linux', 'pal-linux-sgx')}

breathe_domain_by_extension = {
    'h': 'c',
}

try:
    import breathe
except ImportError:
    def generate_doxygen(app):
        pass
else:
    extensions.append('breathe')
    def generate_doxygen(app):
        for p in breathe_projects:
            subprocess.check_call(['doxygen', 'Doxyfile-{}'.format(p)])

def setup(app):
    app.add_stylesheet('css/gramine.css')
    app.connect('builder-inited', generate_doxygen)

todo_include_todos = True

nitpicky = True
nitpick_ignore = [
    ('c:type', 'bool'),
    ('c:type', 'toml_table_t'),
    ('c:type', 'uint8_t'),
    ('c:type', 'uint16_t'),
    ('c:type', 'uint32_t'),
    ('c:type', 'uint64_t'),
    ('c:type', 'int8_t'),
    ('c:type', 'int16_t'),
    ('c:type', 'int32_t'),
    ('c:type', 'int64_t'),
    ('c:type', 'uintptr_t'),
    ('c:type', 'union'),
    ('c:type', 'enum'), # parsing of these seems to be broken:
                        #     WARNING: c:type reference target not found: enum
    # `PAL_HANDLE` has a non complete definition outside of PAL
    ('c:type', 'PAL_HANDLE'),
]

manpages_url = 'https://manpages.debian.org/{path}'

intersphinx_mapping = {'python': ('https://docs.python.org/3', None)}

# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
html_theme = 'sphinx_rtd_theme'
html_theme_options = {
    'logo_only': True,
}
html_logo = 'gramine_logo.svg'

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ['_static']

# Custom sidebar templates, must be a dictionary that maps document names
# to template names.
#
# The default sidebars (for documents that don't match any pattern) are
# defined by theme itself.  Builtin themes are using these templates by
# default: ``['localtoc.html', 'relations.html', 'sourcelink.html',
# 'searchbox.html']``.
#
# html_sidebars = {}


# -- Options for manual page output ------------------------------------------

# One entry per manual page. List of tuples
# (source start file, name, description, authors, manual section).
man_pages = [
    ('manpages/gramine', 'gramine-direct', 'Gramine', [author], 1),
    ('manpages/gramine', 'gramine-sgx', 'Gramine', [author], 1),
    ('manpages/gramine-manifest', 'gramine-manifest', 'Gramine manifest preprocessor', [author], 1),
    ('manpages/gramine-sgx-gen-private-key', 'gramine-sgx-gen-private-key', 'Gramine SGX key generator', [author], 1),
    ('manpages/gramine-sgx-get-token', 'gramine-sgx-get-token', 'Gramine SGX Token generator', [author], 1),
    ('manpages/gramine-sgx-ias-request', 'gramine-sgx-ias-request', 'Submit Intel Attestation Service request', [author], 1),
    ('manpages/gramine-sgx-ias-verify-report', 'gramine-sgx-ias-verify-report', 'Verify Intel Attestation Service report', [author], 1),
    ('manpages/gramine-sgx-quote-dump', 'gramine-sgx-quote-dump', 'Display SGX quote', [author], 1),
    ('manpages/gramine-sgx-sign', 'gramine-sgx-sign', 'Gramine SIGSTRUCT generator', [author], 1),
    ('manpages/is-sgx-available', 'is-sgx-available', 'Check SGX compatibility', [author], 1),
]

# barf if a page is not included
assert (set(str(p.with_suffix(''))
        for p in pathlib.Path().glob('manpages/*.rst')
        if not p.stem == 'index')
    == set(source
        for source, *_ in man_pages))
