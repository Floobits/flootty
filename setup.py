#!/usr/bin/env python

import os

from setuptools import setup

setup(name='Flootty',
      version='0.10',
      description='Floobits collaborative terminal',
      long_description=open(os.path.join(os.path.dirname(__file__), 'README.md')).read(),
      author='Floobits',
      author_email='info@floobits.com',
      url='https://floobits.com/',
      license="Apache2",
      py_modules=['flootty'],
      entry_points={
      'console_scripts': [
          'flootty = flootty:main',
      ]},
      classifiers=[
      'Development Status :: 4 - Beta',
      'Intended Audience :: Developers',
      'License :: OSI Approved :: Apache Software License',
      'Topic :: Terminals',
      'Topic :: Utilities',
      ])
