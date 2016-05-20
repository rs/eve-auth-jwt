#!/usr/bin/env python

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

with open('README.rst', 'r') as f:
    readme = f.read()

setup(
    name='eve-auth-jwt',
    version='1.0.5',
    description='Eve JWT authentication',
    long_description=readme,
    author='Olivier Poitrey',
    author_email='rs@dailymotion.com',
    url='https://github.com/rs/eve-auth-jwt',
    keywords=['eve', 'api', 'rest', 'oauth', 'auth', 'jwt'],
    packages=['eve_auth_jwt'],
    package_dir={'eve_auth_jwt': 'eve_auth_jwt'},
    install_requires=['eve>=0.5.0', 'pyjwt==1.3.0'],
    test_suite='test',
    tests_require=['flake8', 'nose'],
    license='MIT',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Web Environment',
        'Environment :: No Input/Output (Daemon)',
        'Intended Audience :: Developers',
        'Intended Audience :: Telecommunications Industry',
        'License :: OSI Approved :: MIT License',
        'Operating System :: Unix',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.4',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Internet :: WWW/HTTP :: HTTP Servers',
        'Topic :: Security',
    ]
)
