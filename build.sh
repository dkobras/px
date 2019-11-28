#!/bin/sh

pyinstaller --clean --noupx -F --hidden-import gssapi.raw.cython_converters --hidden-import gssapi.raw._enum_extensions.ext_iov_mic --hidden-import keyrings.alt.file px.py
