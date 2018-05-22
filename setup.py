from setuptools import setup, find_packages, os

here = os.path.abspath(os.path.dirname(__file__))
exec(open(os.path.join(here, 'stashokta/version.py')).read())

setup(
    name='stash-okta',
    version=__version__,
    description='Fork of okta-awscli by James Hale',
    packages=find_packages(),
    license='Apache License 2.0',
    author='Ahmad Ragab',
    author_email='aragab@stashinvest.com',
    url='https://github.com/ASRagab/okta-awscli',
    entry_points={
        'console_scripts': [
            'stash-okta=stashokta.okta_awscli:main',
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
