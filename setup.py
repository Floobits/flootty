#!/usr/bin/env python

from setuptools import setup

setup(name='Flootty',
      version='0.07',
      description='Floobits collaborative terminal',
      author='Floobits',
      author_email='info@floobits.com',
      url='https://floobits.com/',
      license="Apache2",
      py_modules=['flootty'],
      entry_points={
      'console_scripts': [
          'flootty = flootty:main',
      ]})
