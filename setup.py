from setuptools import setup, find_packages, os

here = os.path.abspath(os.path.dirname(__file__))
exec(open(os.path.join(here, 'oktaawscli/version.py')).read())

setup(
    name='okta-awscli3',
    version=__version__,
    description='Provides a wrapper for Okta authentication to awscli',
    packages=find_packages(),
    license='Apache License 2.0',
    author='James Hale',
    author_email='james@jameshale.me',
    url='https://github.com/jmhale/okta_awscli',
    entry_points={
        'console_scripts': [
            'okta-awscli=oktaawscli.okta_awscli:main',
        ],
    },
    install_requires=[
        'requests',
        'click',
        'bs4',
        'boto3',
        'ConfigParser'
        ],
)
