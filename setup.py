#!/usr/bin/env python

from setuptools import setup

setup(name='Flootty',
      version='1.10',
      description='Floobits collaborative terminal',
      author='Floobits',
      author_email='info@floobits.com',
      url='https://floobits.com/',
      license="Apache2",
      packages=['flootty'],
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
