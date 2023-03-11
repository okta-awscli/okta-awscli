from setuptools import setup, find_packages, os

here = os.path.abspath(os.path.dirname(__file__))
exec(open(os.path.join(here, 'oktaawscli/version.py')).read())

setup(
    name='okta-awscli',
    version=__version__,
    description='Provides a wrapper for Okta authentication to awscli',
    packages=find_packages(),
    license='Apache License 2.0',
    author='James Hale',
    author_email='james@hale.dev',
    url='https://github.com/okta-awscli/okta-awscli',
    entry_points={
        'console_scripts': [
            'okta-awscli=oktaawscli.okta_awscli:main',
        ],
    },
    install_requires=[
        'requests',
        'click',
        'beautifulsoup4',
        'boto3',
        'ConfigParser',
        'validators',
        ],
    extras_require={
        'U2F': ['python-u2flib-host']
    },
)
