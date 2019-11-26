#!/usr/bin/python

from setuptools import setup,find_packages

setup(
    name='PyTappd',
    version='0.4',
    license='Creative Commons Attribution-Noncommercial-Share Alike license',
    author='Robert Auch',
    author_email='rauch@totalnetsolutions.net',
    long_description=open('README.md').read(),
    classifiers=[
        'Development Status :: 4 - Beta',
        'Indended Audience :: Security Administrators',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.7',
        ],
    package_dir={'':'src'},
    packages=find_packages(where='src'),
    python_requires='>=2.7',
    install_requires=[
        'requests',
        ],
    entry_points={
        'console_scripts': [
            'sample=sample:main',
        ],
    },
)
