#!/usr/bin/python

from setuptools import setup,find_packages

setup(
    name='BIUL',
    version='0.1',
    license='Creative Commons Attribution-Noncommercial-Share Alike license',
    author='Robert Auch',
    author_email='rauch@beyondtrust.com',
    long_description=open('README.md').read(),
    classifiers=[
        'Development Status :: 4 - Beta',
        'Indended Audience :: Security Administrators',
        'Programming Language :: Python :: 3.7',
        ],
    package_dir={'':'src'},
    packages=find_packages(where='src'),
    python_requires='>=3.6',
    install_requires=[
        'requests',
        'cmd',
        ],
    entry_points={
        'console_scripts': [
            'sample=sample:main',
        ],
    },
)
