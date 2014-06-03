#!/usr/bin/env python

from setuptools import find_packages, setup

from flootty import version

setup(name='Flootty',
      version=version.FLOOTTY_VERSION,
      description='Floobits collaborative terminal',
      author='Floobits',
      author_email='info@floobits.com',
      url='https://floobits.com/',
      license="Apache2",
      packages=find_packages(),
      package_data={
          '': ['README.md']
      },
      entry_points={
          'console_scripts': [
              'flootty = flootty.flootty:main',
          ]},
      classifiers=[
          'Development Status :: 5 - Production/Stable',
          'Environment :: Console',
          'Intended Audience :: Developers',
          'License :: OSI Approved :: Apache Software License',
          'Topic :: Terminals',
          'Topic :: Utilities',
      ])
