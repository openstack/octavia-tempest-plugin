# -*- coding: utf-8 -*-
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import datetime
import os
import sys

sys.path.insert(0, os.path.abspath('../..'))
sys.path.insert(0, os.path.abspath('.'))

# -- General configuration ----------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom ones.
extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.viewcode',
    'openstackdocstheme',
    'oslo_config.sphinxext',
    'sphinxcontrib.apidoc',
    'sphinxcontrib.rsvgconverter'
]

# autodoc generation is a bit aggressive and a nuisance when doing heavy
# text edit cycles.
# execute "export SPHINX_DEBUG=1" in your terminal to disable
templates_path = ['_templates']

# The suffix of source filenames.
source_suffix = '.rst'

# The master toctree document.
master_doc = 'index'

# General information about the project.
project = u'octavia-tempest-plugin'
copyright = u'2017-2019, OpenStack Foundation'

# If true, '()' will be appended to :func: etc. cross-reference text.
add_function_parentheses = True

# If true, the current module name will be prepended to all description
# unit titles (such as .. function::).
add_module_names = False

# The name of the Pygments (syntax highlighting) style to use.
pygments_style = 'native'

# A list of ignored prefixes for module index sorting.
modindex_common_prefix = ['octavia_tempest_plugin.']

openstackdocs_repo_name = 'openstack/octavia-tempest-plugin'
openstackdocs_pdf_link = True
openstackdocs_use_storyboard = True

apidoc_output_dir = '_build/modules'
apidoc_module_dir = '../../octavia_tempest_plugin'
apidoc_excluded_paths = []

# -- Options for HTML output --------------------------------------------------

# The theme to use for HTML and HTML Help pages.  Major themes that come with
# Sphinx are currently 'default' and 'sphinxdoc'.
# html_theme_path = ["."]
# html_theme = '_theme'
# html_static_path = ['static']

html_theme = 'openstackdocs'


# Output file base name for HTML help builder.
htmlhelp_basename = '%sdoc' % project

# If false, no module index is generated.
html_domain_indices = True

# If false, no index is generated.
html_use_index = True

# -- Options for LaTeX output -------------------------------------------------

# Fix Unicode character for sphinx_feature_classification
# Sphinx default latex engine (pdflatex) doesn't know much unicode
latex_preamble = r"""
\usepackage{newunicodechar}
\newunicodechar{✖}{\sffamily X}
\setcounter{tocdepth}{2}
\authoraddress{\textcopyright %s OpenStack Foundation}
""" % datetime.datetime.now().year

latex_elements = {
    # The paper size ('letterpaper' or 'a4paper').
    # 'papersize': 'letterpaper',

    # The font size ('10pt', '11pt' or '12pt').
    # 'pointsize': '10pt',

    # Additional stuff for the LaTeX preamble.
    # openany: Skip blank pages in generated PDFs
    'extraclassoptions': 'openany,oneside',
    'makeindex': '',
    'printindex': '',
    'preamble': latex_preamble
}

# Disable usage of xindy https://bugzilla.redhat.com/show_bug.cgi?id=1643664
# Some distros are missing xindy
latex_use_xindy = False

# Fix missing apostrophe
smartquotes_excludes = {'builders': ['latex']}

# Grouping the document tree into LaTeX files. List of tuples
# (source start file, target name, title, author, documentclass
# [howto/manual]).
latex_documents = [(
    'index',
    'doc-octavia-tempest-plugin.tex',
    u'Octavia Tempest Plugin Documentation',
    u'OpenStack Octavia Team',
    'manual'
)]

# The name of an image file (relative to this directory) to place at the top of
# the title page.
# latex_logo = None

# For "manual" documents, if this is true, then toplevel headings are parts,
# not chapters.
# latex_use_parts = False

# If true, show page references after internal links.
# latex_show_pagerefs = False

# If true, show URL addresses after external links.
# latex_show_urls = False

# Documents to append as an appendix to all manuals.
# latex_appendices = []

# If false, no module index is generated.
latex_domain_indices = False
