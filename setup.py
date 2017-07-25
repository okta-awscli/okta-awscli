from setuptools import setup, find_packages

setup(
    name='okta-awscli',
    version='0.1.2',
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
