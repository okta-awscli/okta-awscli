from setuptools import setup, find_packages, os
import sys

here = os.path.abspath(os.path.dirname(__file__))

try:
    from oktaawscli import __version__
except SyntaxError as exc:
    sys.stderr.write(f"Unable to import oktaawscli ({exc}). Are you running a supported version of Python?\n")
    sys.exit(1)

setup(
    name='okta-awscli',
    version=__version__,
    description='Provides a wrapper for Okta authentication to awscli',
    packages=find_packages(),
    license='Apache License 2.0',
    author='James Hale',
    author_email='james@hale.dev',
    url='https://github.com/okta-awscli/okta-awscli',
    python_requires='>=3.8',
    readme = "README.md",
    entry_points={
        'console_scripts': [
            'okta-awscli=oktaawscli.okta_awscli:main',
        ],
    },
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    install_requires=[
        'requests',
        'click',
        'beautifulsoup4',
        'boto3',
        'ConfigParser',
        'validators'],
    extras_require={
        'U2F': ['python-u2flib-host'],
        'FIDO2': ['fido2>=1.1.1'],
    },
)
